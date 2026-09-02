Confirms the mismatch: `Handler#stacks` (in `app/models/shipit/webhooks/handlers/handler.rb`) resolves the target repository/stack via `payload.dig('repository', 'full_name')`, while `WebhooksController#verify_signature` selects which GitHub App's secret to check the HMAC against using a *different* field, `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`).### Title
Signature-verification organization derived from `repository.owner.login` is decoupled from the `repository.full_name` used to select the acted-upon stack, enabling cross-repository webhook forgery when any configured GitHub App has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App (and therefore the HMAC secret) to validate an inbound webhook against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (or `organization.login`). Every downstream `Webhooks::Handlers::Handler` subclass instead resolves the *actual* repository/stack to act on from a completely different, attacker-controlled field: `payload.dig('repository', 'full_name')`. Because these two fields are never cross-checked against each other, an attacker who can produce a valid signature for one configured organization (in particular, any organization whose `webhook_secret` is left blank/`nil`, which `GitHubApp#verify_webhook_signature` treats as "always verified") can forge a webhook whose `repository.full_name` points at a stack belonging to a *different, unrelated* organization/repository and have it processed as authentic.

### Finding Description
- `WebhooksController#verify_signature` selects the app/secret via `repository_owner`: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [1](#0-0) [2](#0-1) 
- `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the selected app's `webhook_secret` is blank: `return true unless webhook_secret`. [3](#0-2) 
- `webhook_secret` is explicitly documented/shipped as an optional, nilable value per organization in a multi-app deployment (e.g. `secrets.development.example.yml`, `secrets_double_github_app.yml`, `docs/setup.md`), so it is realistic for one configured organization to have no secret set while others do. [4](#0-3) [5](#0-4) 
- Once `verify_signature` passes (trivially, for the org with no secret), `WebhooksController#create` dispatches the raw parsed JSON body, unmodified, to the relevant `Shipit::Webhooks::Handlers::Handler` subclasses. [6](#0-5) 
- Every handler determines which `Stack`/`Repository` to act on from `payload.dig('repository', 'full_name')` via `Handler#stacks` / `Handler#repository_name` — a field completely independent from the `repository.owner.login` used for signature routing. [7](#0-6) 
- For example, `PushHandler#process` iterates `stacks.not_archived.where(branch:)` (scoped by the forged `full_name`) and calls `stack.sync_github(expected_head_sha: params.after)`, an attacker-supplied SHA, enqueuing `GithubSyncJob` against a stack in a repository/organization the attacker never authenticated for. [8](#0-7) 

This is the structural analog of the reported bug class: the report's binding is "price charged == price the mint step is gated on"; here the binding that should hold is "organization whose signature is verified == organization/repository the handler acts upon." The code enforces neither an explicit equality between `repository.owner.login` and the owner segment of `repository.full_name`, nor ties the verified app identity to the specific `Repository` looked up by the handler. When the "price" (i.e., the required secret) for the routing organization is zero/absent, the entire binding collapses and any repository name can be substituted downstream.

### Impact Explanation
An attacker who can trigger `verify_webhook_signature` to return `true` for any *one* configured GitHub App (trivial when that org's `webhook_secret` is unset, which is a first-class supported configuration per `docs/setup.md`'s "Using Multiple Github Applications" section) can submit arbitrary, unauthenticated webhook payloads (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) that reference `repository.full_name` values belonging to entirely different, properly-secured organizations/repositories tracked by the same Shipit instance. This lets an unprivileged network attacker:
- Inject fabricated commit statuses/check runs onto tracked commits of unrelated repositories (`status`/`check_suite` handlers act on `Commit`/`Stack` resolved purely from the forged `full_name`).
- Trigger `GithubSyncJob` fetches and archive/unarchive review stacks for repositories the attacker has no relationship with, via `PushHandler`, `pull_request` handlers, etc.
- Manipulate provisioning/label-based archival logic (`LabeledHandler`, `ReopenedHandler`) for review stacks that gate deploy eligibility, indirectly influencing which commits become deployable/merge-able.

This crosses the "cross-repository writes" / "unauthenticated write of stack state" boundary called out as in-scope Critical/High impact, because the write happens against a repository never covered by the signature that was actually checked.

### Likelihood Explanation
Requires only network access to the public webhook endpoint plus knowledge that at least one configured GitHub App in a multi-org Shipit deployment has no `webhook_secret` configured — a state the codebase and shipped example configs explicitly allow and even ship with `webhook_secret: # nil` placeholders. No GitHub credentials, API tokens, or session are needed; the attacker only needs to guess/know the name of one such lightly-configured organization (which may be discoverable from the app's public GitHub App listing or misconfiguration) to unlock forgery against every other tracked repository.

### Recommendation
Bind the verified webhook identity to the actual repository being mutated: require that the organization/owner used to select the verifying `GitHubApp` matches the owner segment of `repository.full_name` used by `Handler#stacks`, and/or refuse to treat a missing `webhook_secret` as an implicit pass — instead, default to rejecting unsigned/unverifiable webhooks for any organization, forcing every configured app to have secret verification enabled before dispatching mutating handlers.

### Proof of Concept
1. Deploy Shipit with two GitHub Apps configured under `secrets.github`: `OrgA` (no `webhook_secret` set) and `OrgB` (properly configured, tracking a real, sensitive stack).
2. POST to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/sensitive-repo"
  }
}
```
No `X-Hub-Signature` header is required to pass verification since `Shipit.github(organization: 'OrgA').verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`).
3. `WebhooksController#create` dispatches the payload to `PushHandler`, which resolves `stacks` from `repository.full_name = "OrgB/sensitive-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and enqueues `GithubSyncJob` for that stack — despite the request never being signature-checked against `OrgB`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-9)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
