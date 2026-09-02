## Finding: Webhook signing‑organization is never bound to the organization/repository the payload mutates

This maps to the same bug class as the Pyth report: a piece of untrusted payload data is used to pick the *verification context* (multiplier / expo → here, the GitHub App / `webhook_secret`), while a *different* field from the same, only partially‑verified payload is later trusted to decide *what gets acted on*. The two fields are never cross‑checked, so passing the signature check for organization A tells you nothing about which organization/repository the handler will actually mutate.

### Root cause

`WebhooksController#verify_signature` picks which GitHub App config (and thus which `webhook_secret`) to HMAC-verify against using a value pulled straight out of the still‑unverified JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` is only used to select the secret (`Shipit.github(organization: repository_owner)` → `verify_webhook_signature`) [3](#0-2) . The HMAC itself is computed over the *raw body*, so it proves the request was signed with *some* configured organization's secret — it does not prove that any particular field inside the JSON (e.g. `organization.login`, `repository.full_name`) matches that organization.

Once the signature is accepted, handlers derive the actual mutation target from *other, independent* fields of the same payload:

- `Handler#repository_name` uses `payload.dig('repository', 'full_name')` to look up the `Repository`/`Stack` to act on [4](#0-3) .
- `MembershipHandler#process` uses `params.organization.login` (a required but otherwise unvalidated string) to create/update a `Team` scoped to that organization, and adds/removes an arbitrary `member.login` from it [5](#0-4) .

Neither of these fields is compared against `repository_owner` (the value that selected the verifying secret). The equality that should hold — `organization authenticated by the signature == organization/repository the handler mutates` — is never enforced.

### Concrete impact path (multi‑org deployment)

In the documented multi‑org configuration, each GitHub organization onboarded to a shared Shipit instance is issued/configures its own GitHub App and `webhook_secret` [6](#0-5) . An org administrator for `OrgA` legitimately knows `OrgA`'s `webhook_secret` (it is theirs to configure when installing the App) but has no privileges over `OrgB`, whose stacks also live on the same Shipit instance.

That administrator can sign an arbitrary JSON body with `OrgA`'s secret while setting the content to reference `OrgB`:
- `repository.owner.login = "OrgA"` (so `verify_signature` selects and validates against `OrgA`'s secret),
- `organization.login = "OrgB"`, `team = {...}`, `member.login = "attacker-controlled-user"` for a `membership` event.

`verify_signature` passes (correct HMAC for `OrgA`), but `MembershipHandler` then creates/updates a `Team` for `OrgB` and adds the attacker‑chosen GitHub login as a member [7](#0-6) . Team membership feeds directly into `Shipit.github_teams` authorization used to gate deploy/merge permissions elsewhere in the app, so this is a cross‑organization escalation into authorization state that the attacker's own organization was never granted. The same decoupling also lets a `push`/`status` payload reference an arbitrary `repository.full_name` belonging to a different org to trigger `stack.sync_github` or commit‑status writes on stacks the signing organization doesn't own [8](#0-7) .

### Title
Webhook organization used for signature verification is never bound to the organization/repository the handler mutates - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the verifying GitHub App/secret using the untrusted `repository.owner.login` (or `organization.login`) field from the JSON body, then handlers separately trust other body fields (`repository.full_name`, `organization.login`, `team`, `member.login`) to decide what to mutate, without ever checking the two match.

### Finding Description
The binding that should hold is: `organization whose webhook_secret validated this request == organization/repository the resulting handler acts on`. `verify_signature` computes the left side from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) , and the HMAC only certifies that the raw body was signed by *that* organization's app. The right side is computed independently by each `Handler` subclass from potentially different fields of the same body (`repository.full_name` in `Handler#repository_name`, or `organization.login`/`team`/`member` in `MembershipHandler`) with no cross-check against the value used for signature selection.

### Impact Explanation
In a multi‑organization Shipit deployment, any org that legitimately controls its own GitHub App `webhook_secret` can forge a webhook body whose "acting" fields reference a *different* onboarded organization/repository. This produces cross‑repository writes (arbitrary `sync_github` triggers, forged commit statuses) and, more critically, unauthorized mutation of `Team`/`Membership` records that back `Shipit.github_teams` authorization — i.e., escalation into another organization's deploy/merge authorization, matching the High-severity criteria for escalation into `Shipit.github_teams` authorization.

### Likelihood Explanation
Requires the attacker to already possess a valid `webhook_secret` for at least one organization configured on the shared Shipit instance (achievable simply by being an admin of that org's GitHub App installation — not privileged access to the *target* org or a Shipit session/API token). Given that, forging the request body is trivial (plain HTTP POST with a computed HMAC), making this a low-effort attack once the precondition is met.

### Recommendation
After `verify_signature` succeeds, re-derive the organization/repository each handler is about to mutate and assert it equals (or is owned by) the organization whose secret validated the request; reject the webhook otherwise. `Handler#repository_name` and `MembershipHandler`'s `organization.login`/`team.organization` should not be trusted independently of `repository_owner`.

### Proof of Concept
1. Configure a multi-org Shipit instance with `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`).
2. As an admin of `OrgA`'s GitHub App, compute `sha1=HMAC(OrgA_secret, body)` for a `membership` event body where `repository.owner.login` (or `organization.login` used for secret lookup) = `"OrgA"`, but the handler-relevant payload fields are set to target `OrgB`: `organization.login = "OrgB"`, `team = {id, name, slug, url}`, `member.login = "attacker-login"`, `action = "added"`.
3. POST to `/webhooks` with header `X-Hub-Signature: sha1=<hmac>` and `X-Github-Event: membership`.
4. `verify_signature` passes because the HMAC matches `OrgA`'s secret [1](#0-0) ; `MembershipHandler#process` then creates/updates a `Team` for `OrgB` and adds `attacker-login` as a member [5](#0-4) , despite the request never being signed by `OrgB`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-44)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
      end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
