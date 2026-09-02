### Title
Webhook signature is verified against the org derived from `repository.owner.login`, while every handler acts on the repository named by the unrelated `repository.full_name` field, both taken from the same unverified body - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub App / `webhook_secret` to validate the `X-Hub-Signature` against by reading `repository.owner.login` (or `organization.login`) straight out of the still‑unverified JSON body, and only *after* that check succeeds does it hand the same raw body to the event handlers. Every handler, however, resolves the target `Stack`/`Repository` using a *different* field of that same unverified body: `repository.full_name` [1](#0-0) . Because these two fields are never cryptographically bound together (the signature only covers the raw bytes, not "this signature authorizes writes to repository X"), an attacker who can produce a valid signature for *any* configured organization can freely choose an unrelated `repository.full_name` to make handlers act on.

### Finding Description
The controller resolves the signing organization like this: [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')`, i.e. from the attacker-supplied JSON body, before any signature has been validated. This value selects which `GitHubApp` config (and thus which `webhook_secret`) is used in `verify_webhook_signature`: [3](#0-2) 

Note also that if the resolved organization's `webhook_secret` is blank/unconfigured, `verify_webhook_signature` returns `true` unconditionally (`return true unless webhook_secret`), and Shipit's own multi-org setup docs show `webhook_secret` as an optional, sometimes-blank field per organization [4](#0-3) .

Once `verify_signature` passes, `create` dispatches the **same raw body** to handlers keyed only by the `X-Github-Event` header: [5](#0-4) 

All handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`, PR handlers) inherit `repository_name`/`stacks` from `Handler`, which reads a *different* field, `repository.full_name`, to look up the `Repository`/`Stack` to mutate: [1](#0-0) 

The binding that should hold is: **organization whose secret authenticated the request == organization/repository that the handler writes to.** Instead, the two are read from independent, attacker-controlled JSON paths in the same unverified payload, so an attacker only needs a valid signature for *some* configured org (or exploits a config where that org's `webhook_secret` is blank) to have the payload's `repository.full_name` point at a completely different org/repo whose stacks then get acted upon — e.g. `PushHandler` enqueues `stack.sync_github` for the target repo's stacks [6](#0-5) , and `MembershipHandler` adds/removes users from `Shipit.github_teams`-backed `Team` records using `organization.login`/`member.login` fields that are likewise unauthenticated against the verified org [7](#0-6) .

This is the direct analog of CL-2021-16's "insufficient validation on deserialization": a field taken from an untrusted blob (there, a curve point; here, `repository.full_name`/`organization.login`) is *acted upon* without being covered by the same validation/authentication step (there, subgroup-membership check; here, HMAC signature) that was applied to a *different* part of the same blob (there, the compressed bytes; here, `repository.owner.login`).

### Impact Explanation
On any Shipit instance configured with multiple GitHub organizations (the documented multi-org setup) or with any organization lacking a `webhook_secret`, an unprivileged network attacker can forge `push`, `status`, `check_suite`, `pull_request`, and `membership` events that are dispatched against a **different** organization's repositories/stacks than the one whose secret (or lack thereof) satisfied `verify_signature`. This can trigger unauthorized `GithubSyncJob`s, fabricate commit statuses used to gate deploys, and mutate `Shipit.github_teams`-derived `Team` membership — an escalation into the app's authorization model and forged repository/stack state, without needing any Shipit session, API token, or the target organization's real webhook secret.

### Likelihood Explanation
Requires only network access to `POST /webhooks` and knowledge/possession of a valid signature for *any one* configured organization (trivial if that organization's `webhook_secret` is unset, which Shipit's own docs show as a normal/optional configuration). No repository write access, GitHub App key, or Shipit credential is required — only the multi-organization deployment pattern the engine explicitly documents and supports.

### Recommendation
Bind the field used to select the verification secret to the field used to resolve the target repository/stack: derive the target repository strictly from the organization/app context that produced a valid signature (e.g., verify against every configured secret and only accept an event whose declared `repository.full_name` organization matches the org that validated it), rather than trusting `repository.owner.login` and `repository.full_name` as independent, unauthenticated inputs from the same body.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md`) with two organizations: `org-a` (attacker has/knows a valid or blank `webhook_secret`) and `org-b` (victim, stacks tracked in Shipit).
2. Attacker crafts a `push` webhook body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
3. Attacker computes/obtains `X-Hub-Signature` valid for `org-a`'s secret (or, if `org-a.webhook_secret` is blank, any value works since `verify_webhook_signature` short-circuits to `true`).
4. `verify_signature` resolves `Shipit.github(organization: "org-a")` and passes.
5. `PushHandler` reads `repository.full_name = "org-b/victim-repo"`, looks up `org-b`'s `Stack`, and enqueues `stack.sync_github` — an unauthorized action on `org-b`'s stack triggered using only `org-a`'s credential material.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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
```
