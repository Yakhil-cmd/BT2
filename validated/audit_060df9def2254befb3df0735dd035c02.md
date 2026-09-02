### Title
Cross-repository `Status` forgery via unscoped `Commit.where(sha:)` lookup enables attacker-timestamped status to displace a victim's real CI result - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target `Commit` purely by SHA (`Commit.where(sha: params.sha)`), with no check that the SHA belongs to the repository named in the incoming webhook payload. Combined with `has_many :statuses, -> { order(created_at: :desc) }` and `Status::Group`'s `uniq(&:context)` (which keeps the first/most-recent-by-`created_at` entry per context), an attacker who owns any repository sharing commit history with the victim (e.g. a public fork) can send a validly-signed webhook from their own repo that writes an attacker-controlled `Status` row onto the victim's `Commit`/stack, with an attacker-chosen `context` and future `created_at`, overriding the real CI result used by `Commit#state`.

### Finding Description
The claimed binding is: *"the most-recent Status for a given context on a commit == the most recent report from the CI system the victim actually configured for that context."* This fails.

Code path:
- `app/models/shipit/webhooks/handlers/status_handler.rb`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 
Unlike every other handler, `StatusHandler` never calls `Handler#stacks` (which scopes lookups via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) [2](#0-1) . It looks up commits solely by `sha` across the entire `commits` table, i.e. across every stack/repository registered in the Shipit instance.

- `WebhooksController#verify_signature` only validates that the payload was signed by the org named in `repository.owner.login` inside the payload; it does not verify that the `sha` field actually belongs to that repository [3](#0-2) . An attacker who owns a repository (e.g. a public fork of the victim's repo, sharing ancestor commit SHAs) can install/trigger a genuine GitHub status webhook for their own repo — which GitHub signs correctly for the attacker's org — while setting `sha` to a commit that is shared history with (and tracked as a `Commit` in) the victim's stack.

- `params` accepts an attacker-supplied `created_at: String` with no validation against server time [4](#0-3) , and it is written through verbatim:
```ruby
def replicate_from_github!(stack_id, github_status)
  find_or_create_by!(stack_id:, state: github_status.state, ..., context: github_status.context, created_at: github_status.created_at)
end
``` [5](#0-4) 
`commit.create_status_from_github!` uses the commit's own (victim's) `stack_id`, so the forged row is created under the *victim's* stack [6](#0-5) .

- `Commit#status` delegates to `Status::Group.compact(self, statuses_and_check_runs)` [7](#0-6) , and `statuses_and_check_runs` is `statuses + check_runs`, where `statuses` is declared `has_many :statuses, -> { order(created_at: :desc) }` [8](#0-7) [9](#0-8) . `Status::Group#initialize` does `statuses.to_a.uniq(&:context)`, and Ruby's `Array#uniq` keeps the *first* occurrence per key — since the underlying array is already ordered by `created_at DESC`, this is effectively "pick the status with the greatest `created_at` per context" [10](#0-9) . Because `created_at` is attacker-supplied, setting it in the future guarantees the forged status wins the per-context selection regardless of the real CI's actual timestamps.

None of the existing guards stop this: `verify_signature` authenticates the payload's claimed org, not the SHA-to-repository binding; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema for `StatusHandler` permits arbitrary `sha`, `context`, and `created_at` strings with no cross-checks against `repository`.

### Impact Explanation
An attacker who controls any GitHub repository that shares commit ancestry with a victim's Shipit-tracked repository (trivially achievable by forking a public victim repo) can inject a `Status` row into the victim's stack for any shared commit, with an attacker-chosen `context` (matching the victim's real CI context name) and an attacker-chosen future `created_at`, causing that forged `success` status to be selected as authoritative by `Commit#state`/`Commit#deployable?`. This can flip a commit from `failure`/`pending` to `success`, enabling continuous-deployment (`ProcessMergeRequestsJob`, `schedule_continuous_delivery`) or manual deploys to proceed against a commit that never actually passed CI — an unauthorized deploy triggered by a payload for one repository mutating another repository's commit/stack, matching the Critical impact category. This is repeatable against any commit SHA shared between the attacker's repo and any victim stack in the same Shipit instance.

### Likelihood Explanation
Preconditions: (1) attacker owns/administers a GitHub repository with the Shipit GitHub App/webhook installed (trivial — fork the victim's public repo), (2) the fork shares at least one commit SHA with the victim's tracked repository (true for any commit before the fork point, which is the common case), (3) the victim's Shipit instance tracks that shared commit in some stack. Attacker cost is a single `POST /repos/{attacker}/{fork}/statuses/{sha}` GitHub API call (or UI equivalent) they can make on their own repository at will — no Shipit credentials, GitHub App keys, or webhook secrets are required. This is fully repeatable and does not require timing luck since `created_at` is attacker-controlled.

### Recommendation
In `StatusHandler#process` (and any other SHA-keyed handler), scope the commit lookup to the repository named in the webhook payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently restrict via `Repository.from_github_repo_name(payload.dig('repository','full_name'))&.stacks&.joins(:commits)`, instead of a bare `Commit.where(sha: ...)`. Additionally, do not trust attacker-supplied `created_at` for ordering/selection purposes — use the server-observed insertion time (or at minimum clamp it to not exceed `Time.current`) when determining the "most recent" status per context in `Status::Group`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual)
test "cross-repo status forgery overrides victim's real CI status" do
  victim_stack = shipit_stacks(:shipit) # tracks repo "victim/app"
  commit = victim_stack.commits.create!(sha: "deadbeef", ...)

  # Real failing status from victim's actual CI, in the past
  commit.statuses.create!(
    stack: victim_stack, context: 'ci/travis', state: 'failure',
    created_at: 1.hour.ago
  )
  assert_equal 'failure', commit.reload.state

  # Attacker's payload: signed for attacker's own org, but references victim's commit sha,
  # forged context matching victim's real CI, future created_at
  forged_payload = {
    'sha' => commit.sha,
    'state' => 'success',
    'context' => 'ci/travis',
    'created_at' => 1.hour.from_now.iso8601,
    'branches' => [{ 'name' => victim_stack.branch }],
    'repository' => { 'full_name' => 'attacker/fork', 'owner' => { 'login' => 'attacker' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(forged_payload)

  # Binding under test: does the most-recent-by-context status equal the victim's real CI report?
  assert_equal 'success', commit.reload.state # currently true -> vulnerable
end
```

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

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

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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
```

**File:** app/models/shipit/commit.rb (L12-13)
```ruby
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :check_runs, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
```

**File:** app/models/shipit/commit.rb (L144-146)
```ruby
    def statuses_and_check_runs
      statuses + check_runs
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

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
```

**File:** app/models/shipit/status/group.rb (L24-32)
```ruby
      def initialize(commit, statuses)
        @commit = commit

        visible_statuses = reject_hidden(statuses.to_a.uniq(&:context))
        missing_contexts = required_statuses - visible_statuses.map(&:context)
        visible_statuses += missing_contexts.map { |c| Status::Missing.new(commit, c) }

        @statuses = visible_statuses.sort_by!(&:context)
      end
```
