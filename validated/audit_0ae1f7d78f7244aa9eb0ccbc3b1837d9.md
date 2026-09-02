### Title
Cross-tenant commit status forgery via unscoped `StatusHandler` webhook processing - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The multi-tenant Shipit webhook pipeline verifies a webhook's HMAC signature against the organization named in the payload, but the `status` event handler then writes CI status data by matching **only** the commit SHA, globally, across every stack/repository hosted on the Shipit instance. This breaks the binding between "the organization whose secret authenticated the request" and "the repository that gets written to," letting a tenant with a legitimate app installation on their *own* organization forge a CI status for a commit belonging to a *completely different* tenant's repository.

### Finding Description
`WebhooksController#verify_signature` selects the HMAC secret to validate against based on `repository.owner.login` (or `organization.login`) taken straight from the unauthenticated payload, then checks the signature with that org's `webhook_secret`: [1](#0-0) [2](#0-1) 

This only proves the request was signed by *some* organization's configured secret — it says nothing about which repository/stack the event is permitted to affect. Most handlers (`PushHandler`, `PullRequest::*Handler`) re-scope their side effects via `Handler#repository_name`/`#stacks`, which look up `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`: [3](#0-2) 

`StatusHandler`, however, never consults `repository`/`stacks` at all. It looks up commits **globally by SHA** and applies the attacker-supplied `state`/`context`/`description` to every matching commit in the entire database: [4](#0-3) 

The binding that should hold is:
`organization authenticated by webhook signature == repository/stack whose commit is written`

Instead, the code enforces:
`organization authenticated by webhook signature == any organization` (used only to pick a valid secret) while
`repository/stack written == whichever stack happens to contain a commit with the same SHA`, with no cross-check against the authenticated organization.

Since this Shipit deployment is explicitly multi-tenant (`config/secrets.development.shopify.yml` and `docs/setup.md` show multiple independent orgs, each with their own `app_id`/`installation_id`/`webhook_secret`, all hitting the same `/github/webhooks` endpoint), a tenant that legitimately owns one org/app installation can compute a valid signature with their own secret while embedding a victim's commit SHA in the JSON body.

The forged status is persisted via `Commit#create_status_from_github!` → `Status.replicate_from_github!`, which triggers real side effects on the victim stack, including enabling CI and scheduling merge/continuous-delivery processing: [5](#0-4) [6](#0-5) 

Those statuses are exactly what gate the automated merge queue (`MergeRequest#any_status_checks_missing?`/`#any_status_checks_failed?` read `head.statuses_and_check_runs`): [7](#0-6) 

### Impact Explanation
An attacker who is a valid tenant on one org/repo of a shared Shipit installation (no special privilege beyond having their own configured GitHub App) can forge required-CI-check "success" statuses for commits belonging to an unrelated victim organization's stack. This can push a malicious/unreviewed pull request past the merge queue's CI gating, resulting in an unauthorized merge into the victim's repository — a cross-repository write that falls squarely in the "unauthorized deploy, rollback or merge" / "cross-repository writes" Critical impact bucket, since it lets one tenant manipulate deployment-relevant state belonging to another tenant it has no relationship or credential with.

### Likelihood Explanation
The only prerequisite is possessing one legitimately configured org/app on the shared instance (an ordinary, unprivileged tenant relationship, not a compromise of the victim). The victim's commit SHA is trivial to obtain (public repos, PR pages, or any read access to the victim's commit history via the GitHub UI/API). No secrets belonging to the victim organization are needed, and the request can be crafted and replayed with a standard HTTP client. This is a high-likelihood issue for any Shipit deployment serving more than one GitHub organization.

### Recommendation
Scope `StatusHandler#process` (and any other handler that mutates persisted state) to the repository/stack identified by the verified organization, e.g. restrict the `Commit.where(sha: params.sha)` lookup to `stacks` derived from `payload.dig('repository', 'full_name')` as the other handlers already do, and additionally verify that this repository's owner matches the organization whose secret validated the signature in `WebhooksController#verify_signature`.

### Proof of Concept
1. Onboard (legitimately) organization `attacker-org` on the shared Shipit instance, with its own `webhook_secret` configured.
2. Identify a commit SHA `S` on the victim's repository/stack that requires CI context `ci/required`.
3. Build a `status` webhook payload:
```json
{
  "sha": "S",
  "state": "success",
  "context": "ci/required",
  "repository": {"owner": {"login": "attacker-org"}}
}
```
4. Sign the raw JSON body with `attacker-org`'s `webhook_secret` (HMAC-SHA1) and POST it to `/github/webhooks` with headers `X-Github-Event: status` and `X-Hub-Signature: sha1=<computed>`.
5. `WebhooksController#verify_signature` succeeds (secret matches `attacker-org`). `StatusHandler#process` finds the victim's `Commit` by SHA `S` (ignoring that it belongs to a different org/stack) and creates a `success` `Status` for it, which can unblock the victim's merge queue / deploy pipeline.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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
