### Title
Cross-repository commit-status forgery via SHA-only lookup that ignores the webhook's own `repository` binding — (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub webhook by selecting a `GitHubApp`/secret based on the organization derived from the payload (`repository.owner.login` / `organization.login`) and HMAC-verifying the raw body against that org's `webhook_secret`. [1](#0-0)  That verification establishes trust in "this event genuinely originates from GitHub for the named organization/repository," but `StatusHandler#process` then acts on the payload using only the commit `sha`, with no scoping back to the `repository` field that was actually part of the authenticated payload:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

This breaks the binding `organization/repository authenticated == repository acted upon`: the field the signature covers and that names the source repo (`repository.full_name`) is never checked against which `Commit`/`Stack` the status update is applied to. Every other handler in this engine (`Handler#stacks`, used by push/check_suite/pull_request handlers) scopes lookups through `Repository.from_github_repo_name(repository_name)`, [3](#0-2)  but `StatusHandler` does not use this helper at all.

### Finding Description
Any two `Stack`s tracked by the same Shipit instance can end up with `Commit` rows sharing an identical `sha` — most commonly when one repository is a fork of another (forks retain the exact SHAs of the commits they were forked from), or when a repository is renamed/re-pointed to the same underlying git history, or simply because two independently configured stacks happen to track branches with a shared ancestor commit.

When GitHub delivers a `status` event for *any* of these repositories, `WebhooksController#verify_signature` correctly authenticates the request as belonging to that repository's owning organization. [4](#0-3)  The payload is then dispatched to `StatusHandler`, whose `params` block only requires `sha`, `state`, and optional fields — it never requires or reads `repository`: [5](#0-4) 

```ruby
params do
  requires :sha, String
  requires :state, String
  accepts :description, String
  ...
end

def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

Because `Commit.where(sha: params.sha)` is global (not scoped by `stack_id`/repository), a `status` event that is 100% legitimately signed for repository A will be applied to **every** `Commit` record across **every** `Stack` in the Shipit install that happens to share that SHA — including commits belonging to repository B, a completely unrelated, more sensitive stack.

### Impact Explanation
Commit statuses directly gate deploy/merge eligibility in this engine: `Commit#deployable?` checks `success? && !blocked?` derived from `status`, and `MergeRequest#any_status_checks_failed?` / `#all_status_checks_passed?` rely on `StatusChecker` over `statuses_and_check_runs`. [6](#0-5)  An attacker who merely controls a low-value repository/fork configured under the same Shipit install can push a webhook-triggering event that stamps a fabricated `"success"` status onto a commit shared with a high-value stack, causing that commit to become `deployable?` or mergeable without ever having genuinely passed CI in the target repository — leading to an unauthorized deploy or merge. This satisfies the "unauthorized deploy/merge via cross-repository writes" impact bucket.

### Likelihood Explanation
Exploitability depends entirely on being able to get a `Commit` with a matching `sha` recorded under the victim `Stack` — trivial for forks (identical SHAs by construction) and plausible for template/monorepo-derived repositories, but not exploitable against arbitrary unrelated third-party SHAs (that would require a SHA collision). No `webhook_secret`, `ApiClient` token, session, or privileged Shipit account is required — only the ability to trigger a genuine, GitHub-signed `status` webhook from an attacker-controlled fork/repository already onboarded into the same multi-tenant Shipit instance.

### Recommendation
Scope `StatusHandler#process` (and any other SHA-keyed handler) to the repository named in the payload, mirroring `Handler#stacks`/`repository_name`, e.g. restrict the `Commit.where(sha:)` lookup to `stacks` (via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) instead of matching by `sha` alone across the whole installation.

### Proof of Concept
1. In a multi-stack Shipit instance, configure `stack_victim` tracking `org/victim-repo`, and fork `org/victim-repo` into `org/attacker-fork` (or otherwise ensure a shared commit SHA `abc123` exists in both, e.g. by forking so the fork shares the initial commit history), and configure `stack_attacker` tracking `org/attacker-fork`.
2. From the attacker-controlled `org/attacker-fork`, cause GitHub to send a `status` webhook for commit `abc123` with `state: "success"` (e.g., by having any CI integration or a manual API call report status against that commit in the fork — GitHub signs this webhook with the real, org-held `webhook_secret`, no secret theft needed).
3. `WebhooksController#verify_signature` verifies successfully (real GitHub signature for the org). [4](#0-3) 
4. `StatusHandler#process` runs `Commit.where(sha: "abc123")`, which returns **both** the commit row under `stack_attacker` and the one under `stack_victim`, and calls `create_status_from_github!` on both, forging a `"success"` status on the victim's commit. [2](#0-1) 
5. `stack_victim`'s commit is now `deployable?`/mergeable despite never having run CI in `org/victim-repo`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-18)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
