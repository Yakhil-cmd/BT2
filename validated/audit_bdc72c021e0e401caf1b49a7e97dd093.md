### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a status webhook from one repository mutate CI state on commits belonging to a different repository/stack - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits purely by the attacker-supplied `sha` string, with no filtering by the repository that authenticated the webhook. Every other handler (`PushHandler`, `PullRequest::*`, `CheckSuiteHandler`) uses the base class's `stacks` helper, which scopes to `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, but `StatusHandler` bypasses this entirely.

### Finding Description
The invariant that should hold is: `status.stack.repository.full_name == payload.dig('repository', 'full_name')` for any `Status` record created as a side effect of a webhook request — i.e., a status event authenticated for repo A must only ever write onto commits belonging to stacks of repo A.

Tracing the code: `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-38) validates the HMAC signature using `Shipit.github(organization: repository_owner)`, where `repository_owner` is `params.dig('repository','owner','login')` (line 59-62). This proves only that the request was signed by a GitHub App/secret belonging to that *organization* — it makes no assertion linking the payload's `sha` field to any actual repository content, since `sha`, `context`, and `state` are entirely attacker-controlled JSON fields [1](#0-0) [2](#0-1) .

`Shipit::Webhooks::Handlers::Handler` defines a `stacks` helper that other handlers use to scope processing to the repo that authenticated the request: `Repository.from_github_repo_name(repository_name)&.stacks || Stack.none` [3](#0-2) .

`StatusHandler#process`, however, ignores this helper and queries the `commits` table globally by bare SHA:
```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

Because `Commit` belongs to a `Stack` (not deduplicated globally) and the `sha` param is fully attacker-controlled string data with no proof-of-possession against the named repository, any request signed by a valid org secret (e.g. an attacker's own onboarded repo/org) can supply an arbitrary `sha` value equal to a victim commit's SHA — a value that is public on GitHub, or trivially learned by watching the victim repo/PR — and `StatusHandler` will iterate every `Commit` row across every stack sharing that SHA (fork-shared history commits, or otherwise identical SHAs) and call `commit.create_status_from_github!(params)` on each, writing a `Status` for arbitrary `context` (e.g. `ci/build`) and `state` onto the victim's commit [5](#0-4) .

`create_status_from_github!` invokes `add_status`, which on a `pending`/`success` transition calls `stack.schedule_merges` and can fire `deployable_status` hooks [6](#0-5) . If the victim stack has `review_stacks_enabled: true, allow_all: true` and requires `ci/build` as a blocking/required status, this write can flip a review stack's commit into a deployable state and trigger `stack.schedule_merges`/continuous delivery, ultimately executing the stack's `shipit.yml` tasks.

None of the existing guards catch this: `verify_signature` only checks the org-level HMAC, not repo/SHA linkage; `ExplicitParameters` (`params do ... end` in `StatusHandler`) only validates types/presence of `sha`/`state`/`context`, not their correspondence to real GitHub data; and `drop_unhandled_event` only checks the event name is registered. There is no model validation tying `Status#stack_id`/`Commit#sha` back to the authenticating repository.

### Impact Explanation
A payload legitimately signed for one repository/organization can write a `Status` (arbitrary `context`, `state`, `description`, `target_url`) onto a `Commit` belonging to an entirely different stack, as long as a `Commit` row with the matching `sha` exists there. This falls squarely into the "payload for one repository mutating another's stack/commit" Critical category. On a victim stack with `review_stacks_enabled true, allow_all`, this can flip required CI context state and trigger `stack.schedule_merges`, effectively forcing a ship/merge decision that the true CI provider for that repository never authorized. The blast radius spans every stack/repository configured in the same Shipit instance that happens to share commit SHAs (common for forks/shared history, or any repo an attacker can get onboarded).

### Likelihood Explanation
Preconditions: the attacker needs the ability to send a validly-signed `status` webhook for *some* organization known to Shipit (e.g., their own onboarded repo/org), and a target commit `sha` that already exists in the victim's `commits` table (via shared git history between fork and upstream, or a previously-synced SHA). No GitHub App private key, `api_clients_secret`, or session is required — only a legitimate webhook secret for an org the attacker controls, which is a normal, low-privilege configuration for anyone who onboards their own repo into a shared Shipit instance. This is inexpensive and repeatable against any stack whose commits share a SHA with the attacker-controlled repo's history.

### Recommendation
Scope `StatusHandler#process` the same way as other handlers: filter `Commit.where(sha: params.sha)` further by `stack_id: stacks.pluck(:id)` (using the base `Handler#stacks` helper, derived from `payload.dig('repository','full_name')`), so a status can only ever be applied to commits belonging to stacks of the repository that authenticated the webhook.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook is scoped to the authenticating repository" do
  victim_stack = shipit_stacks(:shipit) # repository: "shopify/shipit-engine", review_stacks_enabled: true, allow_all: true, requires ci/build
  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)

  attacker_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/build',
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker-org' } }
  }

  # Left side of invariant (expected): status count on victim_commit stays 0
  # Right side (actual, exploited): StatusHandler writes a status regardless of repo
  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end
  # Currently this assertion FAILS: StatusHandler.process finds victim_commit via
  # Commit.where(sha: shared_sha) and calls create_status_from_github!, incrementing
  # victim_commit.statuses.count even though the payload's repository is "attacker/unrelated-repo".
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
