### Title
Webhook signature verification is scoped by `repository.owner.login` while all mutating handlers act on the independently-attacker-controlled `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to check the HMAC signature against using `repository_owner`, a field read straight out of the unauthenticated JSON body. Every webhook handler that actually performs writes (creating/syncing stacks, updating commit statuses, archiving stacks, updating pull requests) instead keys off `repository.full_name`, a *different* field of the same attacker-controlled body. These two fields are never cross-checked, so the "organization whose secret authenticated the request" and "the repository that gets written to" are decoupled — mirroring the LCG bug class where the entity that is validated (`transferFrom`'s expected success path) differs from the entity that is ultimately acted upon (the EscrowVault deposit for a pool with no withdraw path).

### Finding Description
`verify_signature` derives the verification key organization from the payload itself: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` trivially returns `true` when the resolved organization has no `webhook_secret` configured — a state the project's own setup docs and secrets templates treat as a normal, supported configuration (`webhook_secret: # nil`): [3](#0-2) [4](#0-3) 

Meanwhile, every webhook handler resolves the repository/stack to mutate from a completely separate field of the same body — `repository.full_name` — not from `repository.owner.login`: [5](#0-4) [6](#0-5) 

Because the JSON body is entirely attacker-supplied to the public `/webhooks` endpoint (`resources :webhooks, only: :create` in `config/routes.rb`), an attacker can submit `repository.owner.login = "org-with-no-secret"` (satisfying `verify_signature`) together with `repository.full_name = "victim-org/protected-repo"` (the field actually used to resolve which `Repository`/`Stack` gets mutated). The code never confirms that the organization whose secret validated the signature actually owns the repository being acted upon.

### Impact Explanation
This breaks the binding "organization that authenticated == repository that is written," letting an unauthenticated attacker forge GitHub webhook events (`push`, `pull_request`, `status`, `check_suite`, `membership`) targeting any repository/stack configured in Shipit, as long as at least one onboarded GitHub organization is configured without a `webhook_secret` (a state the project documents and ships as a valid configuration in its own examples). Concretely this can:
- Force `GithubSyncJob`/`stack.sync_github` on an arbitrary stack of a different repository, and
- Manipulate `PullRequest`/`review_stack` archival, commit `Status` records, and merge-queue state for that repository,

all without any credential, satisfying the "cross-repository writes" Critical criterion.

### Likelihood Explanation
Likelihood depends on operator configuration: it requires at least one GitHub organization mounted with no (or an empty) `webhook_secret`, which the engine's own setup documentation and secrets templates present as an acceptable, supported setting (`webhook_secret: # nil`). No GitHub App private key, `api_clients_secret`, or Shipit session is needed — only knowledge that such an organization exists, and the ability to POST arbitrary JSON to the public `/webhooks` endpoint.

### Recommendation
After resolving `repository` (or `stack`) inside each handler, verify that `payload.dig('repository', 'owner', 'login')` matches the organization that was actually used to validate the signature in `WebhooksController#verify_signature`, rejecting the event otherwise. Alternatively, derive both the verification key and the repository lookup from the same trusted field, and stop treating `webhook_secret: nil` as an implicitly-trusted bypass for cross-organization installations.

### Proof of Concept
1. Configure (or find deployed) Shipit with two orgs in `github:` config, one of which (`unsecured-org`) has `webhook_secret` unset/nil (a documented, supported configuration).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha already known to exist on victim repo>",
  "repository": {
    "owner": { "login": "unsecured-org" },
    "full_name": "victim-org/protected-repo"
  }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "unsecured-org")`, whose `verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is blank — no `X-Hub-Signature` header is even required. [7](#0-6) 
4. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/protected-repo")` and triggers `stack.sync_github`, a write on a stack belonging to `victim-org`, despite the request only ever proving control of `unsecured-org`. [8](#0-7)

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
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
