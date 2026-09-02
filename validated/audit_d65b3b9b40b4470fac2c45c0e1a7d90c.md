### Title
Cross-tenant webhook forgery: verified webhook organization is never bound to the `repository.full_name` a handler acts on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify a request against using `repository_owner`, a value read straight out of the untrusted JSON body. Once the HMAC check passes, the *entire* raw payload — including an independent `repository.full_name` field — is handed unmodified to event handlers, which use `repository.full_name` (not `repository.owner.login`) to look up the `Stack`/`Repository` to act on. Nothing enforces that these two payload fields describe the same repository, so any organization that has a legitimately configured Shipit GitHub App (and therefore knows its own `webhook_secret`) can forge a signed webhook whose `owner.login` matches its own org (to pass signature verification) while `full_name` points at a completely different tenant's repository.

### Finding Description
`verify_signature` derives the signing key purely from payload content, before/independently of validating that content against the rest of the message: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit::GitHubApp#verify_webhook_signature` HMACs the *raw body*, so the signature does prove the entire body (including `repository.full_name`) was signed by the secret configured for org `repository_owner` — but only that. It never asserts `repository.full_name`'s owner segment equals `repository_owner`.

Once verified, `create` dispatches the same raw `params` to handlers: [3](#0-2) 

All handlers resolve the target `Stack` via `repository.full_name`, completely independent of the field used for signature-key selection: [4](#0-3) 

`Repository.from_github_repo_name` parses the owner straight out of that same, unrelated field: [5](#0-4) 

Because Shipit is a multi-tenant engine (each org configures its own `webhook_secret` under `Shipit.github(organization: X)`), an org `X` that legitimately owns a Shipit GitHub App knows the secret used to authenticate itself. It can send a payload with `repository.owner.login = "X"` (so `verify_signature` picks X's own secret and the HMAC checks out) but `repository.full_name = "Y/target-repo"` where `Y` is a different, unrelated tenant. `PushHandler`, status/check-suite handlers, and PR handlers will all act on stack `Y/target-repo` because they only ever consult `full_name`: [6](#0-5) 

This breaks the binding: **organization authenticated (via `repository_owner`/webhook secret) ≠ repository actually written (via `repository.full_name`)**.

### Impact Explanation
An attacker who legitimately controls one tenant organization onboarded to a shared Shipit instance can forge webhook events targeting any other tenant's repository/stack:
- Force `GithubSyncJob` to run against another org's stack (`PushHandler#process` → `Stack#sync_github`), triggering unwanted GitHub API calls and commit ingestion using the victim's `github_access_token`/App credentials.
- Inject forged commit `status` events, PR `labeled`/`unlabeled` (archive/unarchive), or `check_suite` events for a victim stack's commits, corrupting the CI/deployability signals Shipit relies on to gate merges and deploys.

Since Shipit's merge queue and deploy safety checks consult these very commit statuses/check-suite state, this can enable an unauthorized deploy or merge decision for a repository/stack the attacker does not control — meeting the "unauthorized deploy, rollback or merge"/cross-repository-write bar.

### Likelihood Explanation
Requires that the attacker controls (or has been granted) a legitimate, independently-configured tenant organization on a multi-org Shipit deployment — no session, `ApiClient` token, or GitHub repository write access to the *victim* org is needed. This is a realistic configuration for any Shipit instance shared by multiple organizations/teams, which the engine explicitly supports via per-organization `Shipit.github(organization:)` configuration and `GithubOrganizationUnknown` handling.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), assert that the owner segment of `repository.full_name` matches the verified `repository_owner` before dispatching to handlers; reject (422) any payload where they diverge instead of trusting `full_name` unconditionally.

### Proof of Concept
1. Org `X` operates its own GitHub App on the shared Shipit instance and knows its `webhook_secret`.
2. Attacker (any member with push access to org X's repo, or anyone who can reach X's webhook secret) crafts:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "X" }, "full_name": "Y/victim-stack" }
}
```
3. Computes `X-Hub-Signature` using X's known `webhook_secret` over the raw body.
4. POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "X")` and successfully verifies the signature.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("Y/victim-stack")` and calls `Stack#sync_github(expected_head_sha: params.after)` on the victim's stack, despite the request never being signed by org `Y`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
