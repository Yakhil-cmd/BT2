### Title
Attacker-controlled `created_at` on forged `Status` rows lets a cross-repo forgery permanently outrank the legitimate, same-context CI status - (File: `app/models/shipit/status/group.rb`)

### Summary
`StatusHandler` accepts `created_at` as a raw attacker-supplied `String` and persists it verbatim on the `Status` row via `Status.replicate_from_github!`. Because `Commit#status` derives its authoritative value from `Status::Group`, which selects one representative row per `context` using `uniq(&:context)` over an array ordered by `created_at: :desc`, an attacker who can get a forged status accepted for a victim commit (via the pre-existing sha/repo-unscoped write in `StatusHandler#process`) can set `created_at` to an arbitrary future timestamp and guarantee that forged row is chosen as "current" for that context, overriding legitimate CI updates until real time catches up to the forged timestamp.

### Finding Description
Binding claimed: `Commit#status` (i.e. `Status::Group.compact(commit, statuses_and_check_runs)`) must equal the most recent `Status` from the commit's authentic, authorized CI context — `Commit#status.context_status(context) == statuses.where(context: context).order(created_at: :desc).first` where that first row was genuinely created most recently in real time.

Code path:
- `StatusHandler` declares `accepts :created_at, String` with no format/range validation and no server-side override: [1](#0-0) 
- `process` resolves target commits purely by `sha`, with no repository/owner check binding the payload's `repository.full_name` to the commit's actual stack: [2](#0-1) 
- The forged params flow straight into `Status.replicate_from_github!`, which writes `created_at: github_status.created_at` unmodified: [3](#0-2) 
- `Commit#status` is `Status::Group.compact(self, statuses_and_check_runs)`: [4](#0-3) 
- `statuses` is ordered `created_at: :desc`: [5](#0-4) 
- `Status::Group#initialize` computes the effective, per-context row via `statuses.to_a.uniq(&:context)` — i.e., the FIRST occurrence in the `created_at desc` ordered array wins as the representative for that context, then the result is merely re-sorted alphabetically by context (not by recency) before significance selection: [6](#0-5) 

Exploit flow: an attacker who owns a fork of the victim repository has commits with GitHub SHAs identical to the upstream repository's SHAs (forking preserves commit hashes). The attacker configures their own CI/status sender against their fork and fires a `status` event for that shared SHA with `context` equal to the victim's real CI context (e.g. `ci/travis`) and `created_at` set far in the future (e.g. `1.hour.from_now`). `StatusHandler#process`'s `Commit.where(sha: params.sha)` matches the victim's commit row (no repository check), creating a `Status` on the victim stack. Because this forged row's `created_at` exceeds any subsequent legitimate CI update's `created_at` (which reflects real wall-clock time), `uniq(&:context)` always picks the forged row as the representative for that context in `Status::Group`, and it wins `select_significant_status`'s precedence rules for as long as the forged timestamp remains in the future.

Existing guards do not close this: `ExplicitParameters` only validates type (`String`), not chronology; `verify_signature`/`verify_webhook_signature` authenticate the GitHub App's shared secret, not repository ownership of the SHA; there is no `Repository`/`Stack` binding check in `StatusHandler#process` to ensure the payload's `repository` matches the commit's actual stack.

### Impact Explanation
A successful forged status for a same-context row directly controls `Commit#status`, which gates `deployable?`, continuous-deployment triggers (`ContinuousDeliveryJob`), merge-request auto-merging (`ProcessMergeRequestsJob`), and the UI's shown CI state. This is a payload for one repository (attacker's fork) mutating another repository's (victim's) commit/stack status and can force an unauthorized deploy/rollback/merge decision — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy, rollback or merge"). The attack is repeatable against any commit SHA shared between the attacker's controlled repository and any tracked victim stack (typically forks), and the forged status persists as authoritative until real time exceeds the attacker's chosen future `created_at`, which the attacker can set arbitrarily far ahead.

### Likelihood Explanation
Preconditions: (1) the base cross-repo write path — `Commit.where(sha: params.sha)` unscoped by repository — must be reachable, which is confirmed in this codebase; (2) the attacker needs a commit SHA that also exists in the victim's tracked stack, which is trivially achievable by forking the victim repo (fork commits retain identical SHA1 hashes) or by any shared/cherry-picked commit history; (3) the attacker needs a validly-signed webhook delivery, which they get for free from GitHub's own webhook signing on events from their own repository/fork. No Shipit secrets, sessions, or team membership are required. Cost is low and the technique is fully repeatable.

### Recommendation
- Bind the `status` webhook to the commit's actual stack/repository: in `StatusHandler#process`, restrict lookup to `stacks.commits.where(sha: params.sha)` (using the `Handler#stacks` helper, which resolves stacks strictly from `payload.dig('repository','full_name')`) instead of the global `Commit.where(sha: params.sha)`.
- Do not trust attacker-supplied `created_at` for ordering: ignore/ override it with `Time.current` at write time, or at minimum clamp it to `<= Time.current` and reject/ignore future-dated values.
- Consider making `Status::Group`'s per-context "current" selection also validate that the associated `stack_id`/`context` provenance matches the commit's expected CI configuration.

### Proof of Concept
```ruby
# test/models/status/group_forged_created_at_test.rb
require 'test_helper'

module Shipit
  class ForgedCreatedAtRankingTest < ActiveSupport::TestCase
    test "future-dated forged status outranks legitimate current status for same context" do
      commit = shipit_commits(:first)
      stack = commit.stack

      # Legitimate status, created "now"
      legit = commit.statuses.create!(
        stack_id: stack.id, context: 'ci/travis', state: 'success', created_at: Time.current
      )

      # Simulate cross-repo forged webhook processed by StatusHandler,
      # with attacker-controlled created_at set 1 hour in the future
      forged_params = Webhooks::Handlers::Handler.const_get(:StatusHandler) rescue nil
      github_status = OpenStruct.new(
        state: 'failure',
        description: 'forged',
        context: 'ci/travis', # same context as legitimate status
        target_url: 'http://attacker.example.com',
        created_at: 1.hour.from_now
      )
      commit.create_status_from_github!(github_status)
      commit.reload

      effective = commit.status
      # Binding check: effective status for 'ci/travis' should be the legitimate one,
      # but it is the forged one due to created_at desc + uniq(&:context)
      assert_equal 'failure', effective.state
      refute_equal legit.id, commit.statuses.where(context: 'ci/travis').order(created_at: :desc).first.id == legit.id
    end
  end
end
``` [7](#0-6) [3](#0-2) [5](#0-4) [4](#0-3) [6](#0-5)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L12-12)
```ruby
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
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
