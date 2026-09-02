### Title
Cross-Organization Commit Status Forgery via Unscoped `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` applies an incoming GitHub `status` webhook to **every** `Commit` record that shares the reported `sha`, without checking that the commit belongs to the repository/organization that actually signed and sent the webhook. In a multi-organization Shipit deployment (explicitly supported, see `docs/setup.md` "Using Multiple Github Applications"), this breaks the binding between *the organization whose webhook secret authenticated the request* and *the repository/stack whose commit status is written*, allowing a legitimately-signed status webhook from one organization to silently mark a commit in a completely unrelated stack/organization as CI-`success`, which can unlock an unauthorized deploy.

### Finding Description
`WebhooksController#verify_signature` selects the HMAC secret to validate against based on the payload's claimed repository owner/organization: [1](#0-0) 

Once the signature check passes (proving the request genuinely came from *that* organization's GitHub App), the event is dispatched to handlers purely by event type: [2](#0-1) 

Every other handler scopes its side effects to the repository named in the payload via the base `Handler#stacks`/`repository_name` helper: [3](#0-2) 

`StatusHandler`, however, does not use this repository scoping at all. It looks up commits **globally by `sha`** and writes the status to all matches, regardless of which repository/organization sent the webhook: [4](#0-3) 

The `params` block for this handler also never declares/requires a `repository` field, confirming the repository context is never consulted: [5](#0-4) 

This is the same class of bug as the Solana report: the code that decides *what gets authenticated* (the org used to pick the webhook secret) is not the same as the code that decides *what gets mutated* (any commit anywhere with a matching sha), so the "authenticated organization == repository written" equality is violated. Git SHAs are content-addressed and are commonly identical across forks/mirrors of the same commit tracked as separate `Repository`/`Stack` records in Shipit (a supported multi-org, multi-repo setup), so an attacker only needs to control (or compromise) a legitimate, correctly configured CI/status integration for **any one** organization connected to the Shipit instance — not the target organization — to affect commits recognized elsewhere.

### Impact Explanation
`Commit#create_status_from_github!` persists a `Status` used by `Commit#deployable?` to gate deploys. Because `StatusHandler` writes to any commit matching the sha across all repositories/stacks, a webhook that is fully valid for Organization A can inject a fabricated `success` status onto a commit belonging to Organization B's stack (whenever the same commit content — and thus sha — is present in both, e.g. shared history, forks, or vendored/synced repos). This can flip an otherwise non-deployable commit in an unrelated stack to `deployable?`, enabling an **unauthorized deploy** — squarely in the report's Critical/High bucket ("an unauthorized deploy, rollback or merge").

### Likelihood Explanation
This requires a legitimately signed webhook (no secret needs to be broken/leaked), only that Shipit is configured for more than one GitHub organization (a documented, supported configuration) and that a shared commit sha exists between a repo in the "attacking" organization and a repo tracked in the target stack — realistic for forked/mirrored repositories, shared submodules, or cherry-picked commits, which is common in shared-history multi-repo/multi-org CI pipelines.

### Recommendation
Scope `StatusHandler#process` to commits belonging to the repository that sent the webhook, using the same `repository_name`/`stacks` scoping already used by every other handler (`Handler#stacks`), e.g. restrict `Commit.where(sha: params.sha)` to `stacks.flat_map(&:commits)` or an equivalent `Commit.joins(stack: :repository).where(sha: params.sha, repositories: { ... })` filter derived from `payload.dig('repository', 'full_name')`.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `org-a` and `org-b` (per `docs/setup.md` multi-org instructions), each with a stack tracking commits that happen to share a sha (e.g., `org-b`'s repo is a fork/mirror of a commit that also exists in `org-a`'s repo history).
2. From `org-a`'s properly configured GitHub App/CI, send a legitimate `status` webhook (correctly signed with `org-a`'s `webhook_secret`) reporting `state: success` for the shared `sha`.
3. Observe in `StatusHandler#process` that `Commit.where(sha: params.sha)` matches the commit tracked under `org-b`'s stack as well, and `create_status_from_github!` is called on it — marking that commit `deployable?` in `org-b`'s stack even though `org-b` never sent or authorized the status.
4. Trigger a deploy in `org-b`'s stack for that commit; it now passes the CI check gate it should not have passed.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
  end
end
```
