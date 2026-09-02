## Title
`StatusHandler#process` mutates commits across arbitrary repositories/orgs without re-verifying `repository_owner` against `commit.stack.repository` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` only proves that the request was signed with the `webhook_secret` belonging to the organization named in `params.dig('repository','owner','login')`. `StatusHandler#process` never re-checks that binding: it looks up commits by `sha` alone, globally, and mutates whatever it finds, regardless of which org/repo the matched `Commit`'s `stack.repository` belongs to.

### Finding Description
The broken binding, stated explicitly: `repository_owner` (verified via `Shipit.github(organization: repository_owner).verify_webhook_signature`) should equal `commit.stack.repository.owner` for every `Commit` record the handler is about to mutate. This equality is never checked.

Code path:
1. `WebhooksController#verify_signature` selects the GitHub App/secret using `repository_owner = params.dig('repository','owner','login')` and validates the HMAC signature against that org's `webhook_secret` only: [1](#0-0) . This proves "the sender knows org A's webhook secret," nothing about which commit/stack is safe to touch.
2. `WebhooksController#create` dispatches the raw, unscoped JSON `params` straight to the event handlers: [2](#0-1) .
3. `StatusHandler#process` ignores `payload.dig('repository','full_name')`/the base `Handler#stacks` scope entirely (contrast with `PushHandler#process`, `CheckSuiteHandler#process`, and the `PullRequest::*Handler`s, all of which scope via `stacks` or `Repository.from_github_repo_name(...)`). Instead it does a bare, global lookup by `sha`: [3](#0-2) 
`Commit.where(sha: params.sha)` matches every `Commit` row across every stack/repository/org that happens to share that sha - shas are frequently shared across forks, cherry-picks, and mirrored repos, and are always publicly visible on GitHub regardless of org boundaries.
4. `Commit#create_status_from_github!` → `add_status` then performs real state changes on the matched commit: it emits `Hook.emit(:commit_status, ...)` / `Hook.emit(:deployable_status, ...)` and calls `stack.schedule_merges` when the new status is `pending` or `success`: [4](#0-3) . `schedule_merges` enqueues `ProcessMergeRequestsJob` for that foreign stack, and `Status#after_create` callbacks additionally call `enable_ci_on_stack` and `schedule_continuous_delivery`: [5](#0-4) .

Existing guards that do **not** stop this: `verify_signature` only picks/validates a secret, it does not constrain which records downstream handlers may touch; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema for `StatusHandler` requires `sha`/`state` as free-form strings with no repository binding at all: [6](#0-5) ; and `Handler#stacks`/`Repository.from_github_repo_name` exist and are used by sibling handlers but are simply not called by `StatusHandler`.

### Impact Explanation
An attacker who administers any org/repo already registered in the target Shipit instance (and therefore legitimately possesses that org's `webhook_secret`, as GitHub hands webhook secrets to whoever configures the webhook) can send a `status` event signed with their own org's secret but containing an arbitrary `sha` that they know belongs to a commit tracked under a *different* org's stack. Shipit will accept the signature (it only checks the sender org's secret) and then apply the status to the foreign commit, triggering `Hook.emit(:deployable_status, ...)`, `stack.schedule_merges` (queuing `ProcessMergeRequestsJob` against a stack the attacker never authenticated for), and CI/continuous-delivery scheduling. This is a cross-tenant write: a payload authenticated for org A mutates org B's `Commit`/`Stack` state and can influence merge/deploy scheduling for org B, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Preconditions: the Shipit instance must be multi-tenant (multiple orgs configured under `Shipit.github`), which is an explicitly supported and documented configuration (`config/secrets.development.shopify.yml`, `docs/setup.md`). The attacker needs their own legitimately-configured org/repo webhook secret (low cost - they administer it) and needs to know a target commit's sha, which is public GitHub information. No Shipit session, API token, or victim org's secret is required. The attack is trivially repeatable against any sha the attacker can enumerate from GitHub for any tracked repository.

### Recommendation
In `StatusHandler#process` (and any other handler that queries by `sha`/`ref` without going through `stacks`), scope the lookup to `stacks` derived from `payload.dig('repository','full_name')` (the same authenticated repository used to select the webhook secret), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining through `Commit.joins(stack: :repository).where(sha: params.sha, repositories: { owner: repository_owner_or_full_name })`, so only commits belonging to the authenticated repository can be mutated.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, illustrative):
```ruby
test "status event from org A does not mutate org B's commit with colliding sha" do
  org_a_stack = shipit_stacks(:org_a_stack) # repository.owner == 'org-a'
  org_b_commit = shipit_commits(:org_b_commit) # stack.repository.owner == 'org-b'
  org_b_commit.update!(sha: 'deadbeef' * 5)

  payload = {
    'sha' => org_b_commit.sha,
    'state' => 'success',
    'repository' => { 'full_name' => org_a_stack.repository.full_name, 'owner' => { 'login' => 'org-a' } }
  }

  # Binding under test, stated explicitly before tracing:
  assert_not_equal 'org-a', org_b_commit.stack.repository.owner

  assert_no_difference -> { org_b_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end
```
Currently this assertion fails: `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` increments `org_b_commit.statuses.count` because `StatusHandler#process` matches purely on `sha`, proving the `repository_owner == commit.stack.repository.owner` binding is not enforced.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```
