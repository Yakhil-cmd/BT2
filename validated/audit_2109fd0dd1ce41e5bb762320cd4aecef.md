This confirms the vulnerability. `StatusHandler#process` queries `Commit.where(sha: params.sha)` globally across the entire `commits` table with no join or filter on `stack`, `repository`, or the `payload`'s `repository.full_name`/`repository_owner`, unlike other handlers (e.g. the base `Handler#stacks` helper, which correctly scopes via `Repository.from_github_repo_name(repository_name)&.stacks`) — `StatusHandler` bypasses that scoping entirely and calls `commit.create_status_from_github!(params)` for every matching row, in every `Stack`, regardless of which repository authenticated the webhook.### Title
Cross-repository Status forgery via unscoped `Commit.where(sha:)` in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up every `Commit` row that matches the incoming `sha`, with no filter on the repository/stack that the webhook actually belongs to, then writes a `Status` onto each match. Because git commit SHAs are content-addressed, any two `Stack`s that share commit history (forks, mirrors, template-generated repos, or any coincidental content collision) will have `Commit` rows with identical `sha` values across otherwise unrelated tenants, so one verified webhook can mutate `Status`/CI state for stacks the sender does not own.

### Finding Description
The claimed binding is: `number of Stacks mutated by one verified status payload == 1` (the `Stack` that owns the payload's `repository.full_name`). The actual code breaks this:

```ruby
# app/models/shipit/webhooks/handlers/status_handler.rb
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

Note that the base `Handler` class already provides the correct scoping primitive — `stacks`, which resolves via `Repository.from_github_repo_name(repository_name)&.stacks`, tying the payload to only the repository that owns it: [2](#0-1) 

`StatusHandler` does not use `stacks` at all; it queries the entire `commits` table by `sha` only. `Commit` rows carry a `stack_id` (`belongs_to :stack`) but that column is never checked against the requesting repository [3](#0-2) , and `create_status_from_github!` unconditionally creates the `Status` under whatever `stack_id` the found `Commit` belongs to via `statuses.replicate_from_github!(stack_id, github_status)` [4](#0-3) [5](#0-4) .

`verify_signature` in `WebhooksController` only proves that the payload was signed for the org/app matching `repository_owner` in the payload (`Shipit.github(organization: repository_owner)`); it does not, and cannot, constrain which `Commit`/`Stack` rows the handler is allowed to touch [6](#0-5) . Once a payload passes signature verification for its own repository/org, `StatusHandler` is free to mutate any `Stack` whose `Commit` table happens to contain the same `sha`.

Attack flow: an attacker who legitimately owns/controls a repository that is onboarded to Shipit (their own fork, mirror, or a repo sharing history with a victim's tracked repo — e.g. via `git fork`, subtree, or template repos, any of which reproduce identical SHA‑1 commit IDs for shared content) triggers a genuine, correctly-signed `status` webhook from their own repository/org referencing a `sha` that is also present as a `Commit` row in a victim `Stack` (typically an ancestor/shared commit). `StatusHandler.call` then walks every `Commit` with that `sha` across the whole database and writes a forged `Status` (e.g. `state: "success"`) into the victim `Stack`, which can trigger `stack.schedule_merges`, `enable_ci_on_stack`, and downstream deploy-eligibility logic (`add_status` in `commit.rb`) [7](#0-6) .

None of the listed guards prevent this: `verify_signature` validates only that the payload came from *a* legitimate GitHub org/app, not that the affected `Commit`/`Stack` belongs to that org; the `ExplicitParameters` schema in `StatusHandler` only validates field types (`sha`, `state`, etc.), not repository ownership [8](#0-7) ; `drop_unhandled_event`, `force_github_authentication`, `User#authorized?`, `require_permission!`, and the `stacks` scope in the base `Handler` class are simply never invoked by `StatusHandler`.

### Impact Explanation
A single verified webhook from an attacker-controlled repository writes a `Status` row (and can flip `commit.state`) onto every `Stack` sharing that commit `sha`, regardless of tenant boundary — this is a payload for one repository mutating another's stack/commit, matching the Critical category. Consequences include falsely marking CI as `success` on a victim stack, enabling `stack.schedule_merges` and merge-queue progression, and toggling `deployable_status`, all without the attacker having any relationship, access, or permission to the victim repository/stack. The attack is repeatable against any `sha` value known or discoverable in advance (shared ancestor commits between forks/mirrors are common and enumerable by the attacker, since they control one side of the fork relationship).

### Likelihood Explanation
Preconditions: the attacker must own/control a repository that is legitimately connected to Shipit (so a `status` webhook from it passes `verify_signature`), and that repository must share at least one commit SHA with a targeted victim `Stack`'s tracked commits — a realistic scenario for forks, mirrors, or repos created from the same template/subtree history. No Shipit secrets, sessions, or elevated GitHub permissions are required beyond normal use of a repo the attacker legitimately owns. The attacker cost is low: trigger any commit status change (via GitHub UI/API on their own repo) for a shared SHA.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to only the `Stack`s owned by the payload's repository, mirroring the base `Handler#stacks` helper, e.g. iterate `stacks.flat_map { |stack| stack.commits.where(sha: params.sha) }` (or join `commits` to `stacks` filtered by `Repository.from_github_repo_name(repository_name)`), instead of an unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest plan (unit-level, no live GitHub, targeting `StatusHandler` directly):

```ruby
test "StatusHandler only creates a Status for the stack owning the payload's repository" do
  stack_a = shipit_stacks(:shipit)          # repo A, e.g. "shopify/shipit-engine"
  stack_b = shipit_stacks(:cyclimse)        # unrelated repo B, different tenant

  shared_sha = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
  commit_a = stack_a.commits.create!(sha: shared_sha, author: shipit_users(:walrus),
    authored_at: Time.now, committer: shipit_users(:walrus), committed_at: Time.now, message: "a")
  commit_b = stack_b.commits.create!(sha: shared_sha, author: shipit_users(:walrus),
    authored_at: Time.now, committer: shipit_users(:walrus), committed_at: Time.now, message: "b")

  payload = {
    'sha' => shared_sha, 'state' => 'success',
    'repository' => { 'full_name' => stack_a.github_repo_name, 'owner' => { 'login' => stack_a.repository_owner } }
  }

  assert_difference -> { commit_a.statuses.count }, 1 do
    assert_no_difference -> { commit_b.statuses.count } do
      Shipit::Webhooks::Handlers::StatusHandler.call(payload)
    end
  end
end
```

Binding under test: expected `commit_b.statuses.count` delta == 0 (only `Stack` `stack_a`, owner of the payload, should be mutated); current code makes both `commit_a` and `commit_b` receive a `Status`, so the `assert_no_difference` on `commit_b` fails, proving the cross-tenant mutation.

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

**File:** app/models/shipit/commit.rb (L11-12)
```ruby
    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
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
