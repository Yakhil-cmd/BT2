### Title
Cross-repository commit status forgery via unscoped `StatusHandler` webhook processing - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The GitHub webhook signature verification in `WebhooksController` authenticates a webhook against the GitHub App/organization identified by the `repository`/`organization` field of the *same* payload it is verifying, but `StatusHandler`, one of the handlers invoked after that check passes, writes commit statuses to **any** `Commit` row in the database that matches the submitted `sha`, without re-checking that the commit belongs to the repository/organization that was actually authenticated. This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App (and thus the webhook secret used for HMAC verification) purely from attacker-supplied payload fields: [1](#0-0) [2](#0-1) 

This only proves that the request came from *some* GitHub organization that legitimately owns the `repository_owner`/`organization.login` named in the payload — it does not restrict which Shipit-tracked data the resulting handler is allowed to mutate.

Most handlers correctly re-derive scope from the same repository field via the shared `Handler#stacks`/`repository_name` helper, e.g. `PushHandler` and `CheckSuiteHandler` operate only on stacks belonging to `Repository.from_github_repo_name(repository_name)`: [3](#0-2) [4](#0-3) 

`StatusHandler`, however, ignores this scoping helper entirely and looks up commits globally by SHA alone: [5](#0-4) 

Because git commit hashes are content-addressed, any commit shared across repository history (a public fork, a mirrored/imported repository, or simply a widely-reused root/empty commit) can have the identical SHA1 in a repository the attacker legitimately controls and in a completely unrelated repository/stack tracked by this Shipit instance. An attacker who only administers their own (unprivileged, low-value) GitHub organization/repository — enough to have a valid, distinct webhook secret for `Shipit.github(organization: their_org)` — can trigger a real, validly-signed `status` webhook from their own repository whose `sha` matches a commit that also exists in a victim stack. `StatusHandler` will then update the status (`state`, `context`, `description`, `target_url`, etc.) on the victim's `Commit` row, regardless of the fact that the authenticated organization has no relationship to that stack/repository.

### Impact Explanation
This is a cross-repository write: a webhook cryptographically authenticated for organization/repo A is used to mutate commit-status state belonging to organization/repo B, which the attacker has no access to in Shipit. Commit statuses drive Shipit's CI/deployability signal (`create_status_from_github!`), so an attacker can inject fabricated green/red CI statuses onto a victim's tracked commits, potentially unblocking or corrupting deploy readiness checks for a stack they do not own — matching the "cross-repository writes" / "unauthorized deploy" criteria in the Critical bucket.

### Likelihood Explanation
Requires only an unprivileged GitHub organization/repository whose GitHub App is configured in this Shipit instance (a low bar — any onboarded org qualifies) and a commit SHA collision achievable through ordinary git mechanics (shared history via fork/mirror, or well-known reused commits), not a cryptographic SHA1 break. No Shipit account, `ApiClient` token, or repository write access to the victim repo is needed.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the request, consistent with the other handlers, e.g. restrict the lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (using the `Handler#stacks`/`repository_name` helper) instead of a bare, instance-wide `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Attacker registers/owns GitHub org `attacker-org` with a repo that is a fork or mirror sharing commit history with victim's tracked repo `victim-org/app` (so some commit SHA `S` exists in both).
2. Shipit has a GitHub App/webhook secret configured for `attacker-org` (standard onboarding, not privileged access to `victim-org`).
3. Attacker causes GitHub to send (or replays) a validly-signed `status` event for `attacker-org`'s repo with `sha: S`, `state: "success"`, arbitrary `context`/`description`/`target_url`.
4. `WebhooksController#verify_signature` succeeds because the HMAC is valid for `attacker-org`'s secret.
5. `StatusHandler#process` executes `Commit.where(sha: S).each { |c| c.create_status_from_github!(params) }`, which matches the victim's `Commit` row for `victim-org/app` as well, writing a forged status onto it. [6](#0-5)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
