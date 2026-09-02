### Title
`check_suite` webhook authenticated by one GitHub organization's secret mutates a different organization's stack (`owner`/`full_name` split) - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to validate the request using `repository.owner.login` (via `repository_owner`), while `Shipit::Webhooks::Handlers::Handler#stacks` resolves the repository/stacks to mutate using `repository.full_name`, an entirely separate, attacker-controlled field. A `check_suite` payload can therefore be signed (or trivially pass verification) as one organization while causing `CheckSuiteHandler` to reschedule check-run refreshes for commits belonging to a stack of a completely different repository/organization. The `review_stacks_enabled` flag is unrelated to this path: `CheckSuiteHandler` never reads it, so the claimed "provision precedence" amplification does not apply here.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:
`organization_that_authenticated_request (repository_owner = params.dig('repository','owner','login'))` == `organization_that_owns_the_mutated_stack (Repository.from_github_repo_name(params.dig('repository','full_name')))`.

Trace:
- `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and `repository_owner` is defined purely from `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` immediately if that organization has no `webhook_secret` configured: `return true unless webhook_secret` [3](#0-2) . If the attacker names such a no-secret org as `repository.owner.login`, the signature check passes unconditionally regardless of the actual signature header sent.
- On success, `WebhooksController#create` dispatches the raw parsed JSON to every handler for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3) .
- `CheckSuiteHandler#process` resolves the target stacks via the base `Handler#stacks`, which uses `repository_name = payload.dig('repository', 'full_name')` — a field completely independent of `repository.owner.login` used above for signature selection: `Repository.from_github_repo_name(repository_name)&.stacks` [5](#0-4) .
- `CheckSuiteHandler#process` then matches stacks by `params.check_suite.head_branch` and, for matching commits by `params.check_suite.head_sha`, calls `schedule_refresh_check_runs!` [6](#0-5) , which enqueues `RefreshCheckRunsJob.perform_later(commit_id: id)` [7](#0-6) . That job eventually calls `refresh_check_runs!`, which fetches from GitHub via `stack.github_api.check_runs(...)` and writes (`create_or_update_check_run_from_github!`) into the *victim* stack's commit records [8](#0-7) .

Attacker request: POST `/webhooks` with header `X-Github-Event: check_suite`, body `{"repository": {"owner": {"login": "attacker-no-secret-org"}, "full_name": "victim-org/victim-repo"}, "check_suite": {"head_branch": "<victim-stack-branch>", "head_sha": "<victim-commit-sha>"}}`. Because `attacker-no-secret-org` has no configured `webhook_secret` in `Shipit.github_teams`/app config, `verify_signature` passes trivially with any or no `X-Hub-Signature`. `CheckSuiteHandler` then operates on `victim-org/victim-repo`'s stacks and schedules a background job that writes state (check-run rows) for a repository/organization that never authenticated the request.

Existing guards do not prevent this: `drop_unhandled_event` only checks the event type is registered, not repository ownership; `ExplicitParameters` schema on `CheckSuiteHandler` only validates the shape of `check_suite.head_sha`/`head_branch`, not `repository` consistency; there is no code anywhere that cross-checks `repository.owner.login` against `repository.full_name`'s owner segment.

The `review_stacks_enabled` flag, checked in `app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb`, `unlabeled_handler.rb`, `opened_handler.rb`, `reopened_handler.rb`, has no bearing on `CheckSuiteHandler`, which does not reference this flag at all. The premise that a "provision precedence bug" amplifies effects specifically through `check_suite` on a `review_stacks_enabled: false` stack is not supported by the code — the split vulnerability triggers identically whether `review_stacks_enabled` is true or false, since it only requires that a `Stack` with a matching `branch` already exists for the target repository.

### Impact Explanation
An unprivileged attacker can cause writes (check-run refresh data) against commits belonging to a repository/stack they do not own and never authenticated for, by exploiting the mismatch between the org used for signature verification (`repository.owner.login`) and the org/repo used to resolve the mutated stack (`repository.full_name`). This matches the Critical category "a payload for one repository mutating another's stack, commit." The effect here is limited to what `CheckSuiteHandler` does — scheduling `RefreshCheckRunsJob`, which reads from GitHub and updates `check_runs` rows on the victim's commit — not direct code execution. Repeatable against any repository/stack whose branch name and a known/guessable commit SHA the attacker can supply, as long as some organization configured in Shipit lacks a `webhook_secret` (or the attacker can otherwise pass `verify_webhook_signature` for the org they claim).

### Likelihood Explanation
Requires: (1) at least one organization known to `Shipit.github_teams`/app config configured without a `webhook_secret` (so `verify_webhook_signature` returns `true` unconditionally) — this is an operator-configuration precondition, not directly attacker-controlled; (2) a victim stack existing with a specific `branch` and a commit `sha` the attacker can supply/guess. Attacker cost is a single unauthenticated HTTP POST to `/webhooks`; fully repeatable. The `review_stacks_enabled` state of the victim stack does not affect feasibility.

### Recommendation
Verify the webhook signature and resolve the mutated repository/stack using the *same* source of truth. Either verify the signature using the organization derived from `repository.full_name` (not `repository.owner.login`), or after signature verification, assert that `repository.owner.login` matches the owner segment of `repository.full_name` before dispatching to handlers, rejecting the request (e.g., `head(422)`) on mismatch.

### Proof of Concept
Add to `test/controllers/shipit/webhooks_controller_test.rb` (or a new handler test):
1. Configure two orgs in test `Shipit.github_teams`/app config: `"attacker-org"` with no `webhook_secret`, and `"victim-org"` with a `webhook_secret`.
2. Create `victim_repo = Repository.create!(name: "victim-repo", owner: "victim-org")`, `victim_stack = victim_repo.stacks.create!(branch: "main", environment: "production")`, and a `Commit` on it with a known `sha`.
3. POST to `/webhooks` with header `X-Github-Event: check_suite` and body:
   `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}, "check_suite": {"head_branch": "main", "head_sha": "<commit.sha>"}}`, with an arbitrary/invalid `X-Hub-Signature`.
4. Assert response is `200`/`204` (not `422`), i.e. signature check passed using `attacker-org`'s (secret-less) config — the equality `repository_owner_used_for_auth == organization_owning_full_name_repo` is `"attacker-org" != "victim-org"` yet the request is accepted.
5. Assert `RefreshCheckRunsJob` was enqueued with `commit_id: victim_commit.id` (e.g., via `assert_enqueued_with`), proving the victim stack's commit was mutated by a request authenticated under a different organization's (non-)secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/commit.rb (L152-154)
```ruby
    def schedule_refresh_check_runs!
      RefreshCheckRunsJob.perform_later(commit_id: id)
    end
```

**File:** app/models/shipit/commit.rb (L186-196)
```ruby
    def refresh_check_runs!
      paginated_check_runs do |check_runs|
        check_runs.each do |check_run|
          create_or_update_check_run_from_github!(check_run)
        end
      end
    end

    def create_or_update_check_run_from_github!(github_check_run)
      check_runs.create_or_update_from_github!(stack_id, github_check_run)
    end
```
