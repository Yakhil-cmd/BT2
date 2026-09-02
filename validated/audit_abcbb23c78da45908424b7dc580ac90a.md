### Title
Webhook signature verification is keyed by the payload's own `repository.owner.login`, letting a webhook whose org has no configured secret impersonate any other organization's repository and grant unauthorized team membership / trigger deploy checks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App's HMAC secret to validate against by reading `repository.owner.login` (or `organization.login`) straight out of the *unauthenticated* request body, then calls `Shipit.github(organization: repository_owner).verify_webhook_signature`. `GitHubApp#verify_webhook_signature` in turn returns `true` unconditionally whenever that org's `webhook_secret` is blank/unset, since the docs explicitly mark the webhook secret as *optional*. Once "verified", every downstream handler (`PushHandler`, `MembershipHandler`, `StatusHandler`, pull-request handlers, etc.) resolves the repository/stack to act on from a *different* field of the same untrusted payload (`repository.full_name`, `params.organization.login`, etc.) with no cross-check that it matches the org whose secret (or lack thereof) authorized the request.

### Finding Description
The binding that should hold is: **organization that authenticated == repository/organization that is written**. Instead:

- `verify_signature` derives the signing org from `repository_owner` computed from the payload body itself: [1](#0-0) [2](#0-1) 

- `GitHubApp#verify_webhook_signature` treats a missing/blank `webhook_secret` as automatic success: [3](#0-2) 

- Handlers then act on an entirely separate identifier taken from the same unauthenticated payload — e.g. `MembershipHandler` trusts `params.organization.login` and `params.team`/`params.member` to create teams and grant membership: [4](#0-3) 
  and generic handlers resolve the acted-upon repository via `payload.dig('repository', 'full_name')`, a field never covered by any per-org signature comparison to the org used to select the secret: [5](#0-4) 

Setup docs confirm the webhook secret is optional per app, and that multiple GitHub Apps/organizations can be configured on one Shipit instance: [6](#0-5) [7](#0-6) 

In a multi-organization Shipit deployment (explicitly supported, as shown above), if any one configured organization is set up without a `webhook_secret` (a valid, documented configuration), an unauthenticated attacker can send a POST to `/webhooks` with `X-Github-Event: membership` (or `push`/`status`) and a body claiming `repository.owner.login`/`organization.login` equal to that secret-less org, while `team`, `member.login`, or `repository.full_name` name resources belonging to a *different*, properly-secured organization tracked by the same Shipit instance. `verify_signature` will pass (secret is blank ⇒ `verify_webhook_signature` returns `true`) and the handler will execute against the unrelated org/repo, because nothing ties the "organization that authenticated" (or, here, that trivially passed verification) to the organization/repository the handler ultimately writes.

This mirrors the reported bug class: a value used for the trust decision (`repository_owner` used to pick a webhook secret) is a different field than the value the acted-upon state is derived from (`organization.login`, `team`, `member.login`, `repository.full_name`), and the "verification" step does not bind them together.

### Impact Explanation
Concretely reachable, unprivileged, unauthenticated impact:
- `MembershipHandler` creates/deletes `Team` and `Membership` rows and can add an attacker-chosen GitHub login to any `Shipit.github_teams`-equivalent team object tracked by the instance, which is used elsewhere for authorization decisions (`current_user.authorized?` checks team membership) — this is an escalation into `Shipit.github_teams` authorization (High), reachable purely by an org boundary confusion, not by compromising any secret belonging to the target org.
- `StatusHandler`/`PushHandler` can inject fabricated commit statuses / trigger `sync_github`, potentially unblocking CI-gated deploys for stacks that belong to the properly-secured organization, without ever holding that organization's webhook secret.

The severity is bounded by the precondition that at least one configured GitHub App entry in `config/secrets.yml` lacks a `webhook_secret` (documented as optional), which is a realistic, in-scope operational configuration rather than a hypothetical one, and by the engine's own code failing to bind the two identifiers together regardless of that precondition.

### Likelihood Explanation
Requires only an HTTP POST to the public `/webhooks` endpoint with a crafted JSON body and the correct `X-Github-Event` header — no credentials, tokens, or GitHub App access needed. Likelihood is directly tied to whether the operator has configured any org without a webhook secret in a multi-org install; this is explicitly supported and documented as optional, making the precondition realistic for shared/multi-tenant Shipit deployments.

### Recommendation
- Do not allow `webhook_secret` to be optional/blank as a silent bypass; require it (or fail closed) for every configured GitHub App/organization.
- Bind the signature-verifying organization to the organization/repository actually acted upon: after selecting the app via `repository_owner`, verify that `repository.full_name`'s owner and `organization.login` (when present) equal `repository_owner`, and reject mismatches before handlers run.
- Consider deriving the signing app not from attacker-controlled payload content but from a per-installation identifier tied to the route/App config.

### Proof of Concept
1. Configure Shipit with two orgs in `config/secrets.yml`, e.g. `orgA` (no `webhook_secret` set) and `orgB` (has a real, secret-protected GitHub App and a team used for authorization).
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": 48, "name": "orgB-admins", "slug": "orgb-admins", "url": "https://example.com" },
  "organization": { "login": "orgA" },
  "member": { "login": "attacker-github-login" },
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgA/whatever" }
}
```
3. Because `repository_owner` resolves to `orgA`, `Shipit.github(organization: 'orgA').verify_webhook_signature` is called; since `orgA` has no `webhook_secret`, it returns `true` unconditionally per `lib/shipit/github_app.rb` line 77, without checking `X-Hub-Signature` at all.
4. `MembershipHandler#process` runs, creating/updating the `orgB-admins` `Team` record (keyed by `github_id: 48`, matching a real team used for `Shipit.github_teams` authorization) and adding `attacker-github-login` as a member — with no possession of `orgB`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
