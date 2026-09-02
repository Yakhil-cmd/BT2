### Title
Cross-repository Status write via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits globally by `sha` with no repository scoping, unlike `PushHandler` and the pull-request handlers, which restrict their side effects to `stacks` derived from `Repository.from_github_repo_name(payload['repository']['full_name'])`. If two `Repository` records each own a `Commit` row with the same `sha` (plausible for forks/shared history under the same or a peer GitHub organization), a signed status webhook naming one repository will write a `Status` against the other repository's commit/stack.

### Finding Description
The claimed binding is: `Handler#stacks` (scoped by `repository_name = payload.dig('repository','full_name')`, via `Repository.from_github_repo_name(repository_name)&.stacks`, [1](#0-0) ) should equal the set of stacks whose `Commit`/`Status` rows get mutated by the handler. For `PushHandler` this holds: it explicitly calls `stacks.not_archived.where(branch:)` before mutating anything, [2](#0-1) . For `StatusHandler` it does not hold: `#process` never references `stacks` or `repository_name` at all, it only does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, [3](#0-2) . The `params` schema only requires `sha`, `state`, and optional fields; `repository` is parsed by the base `Handler#initialize` into `payload` but is unused by `StatusHandler`, [4](#0-3) .

Root cause: `Commit.sha` is not globally unique across `Repository`/`Stack` boundaries in the schema as used here — `Commit.where(sha:)` can match rows belonging to unrelated stacks/repositories. A GitHub commit `sha` is a hash of tree+metadata; unmodified commits shared between a fork and its upstream (or between two repositories with common history) retain identical `sha` values. If Shipit tracks two such repositories as separate `Stack`s (a realistic, non-crypto-collision scenario for orgs mirroring/forking repos), any signed `status` webhook that references that shared `sha` will call `create_status_from_github!` on the commit rows of **all** repositories that happen to share it — not just the one identified in `payload['repository']['full_name']`.

Path traced: `WebhooksController#create` → `verify_signature` (validates the payload against the org derived from `repository.owner.login` in the payload, not the actual commit owner) → `Shipit::Webhooks.for_event('status')` → `StatusHandler.call(params)` → `StatusHandler#process`, [5](#0-4) . The signature check (`verify_signature`) only proves the payload was signed by the GitHub App/organization named in the payload's `repository.owner.login` — it says nothing about which `Commit`/`Stack` rows the `sha` will touch, so it does not close this gap.

Existing guards checked and found insufficient for this specific path: `drop_unhandled_event` and `verify_signature` only gate at the controller level and are event/org-based, not commit/stack-based; the `ExplicitParameters` schema for `StatusHandler` only validates types of `sha`/`state`/etc., not repository ownership; `Repository.from_github_repo_name` and `Handler#stacks` exist but are simply never invoked by `StatusHandler#process`.

### Impact Explanation
A successfully signed `status` webhook (signed for the attacker's own org/repo) can write a `Status` row onto a `Commit` belonging to a completely different `Repository`/`Stack`, potentially: flipping CI state (`success`/`failure`/`pending`) for a stack not owned by the sender, which per `Commit#create_status_from_github!`/deployable-status logic can influence continuous-deployment triggers, merge-request auto-merge logic (`ProcessMergeRequestsJob`), or release status gating on the victim stack. This is a repository-scope bypass: a payload legitimately signed for repository A can mutate state belonging to repository B. Blast radius is limited to Shipit installations that track multiple `Repository` records sharing commit history (forks, template repos, mirrored history) under the same or trusted GitHub App/org configuration — this matches the "Critical: a payload for one repository mutating another's ... commit" category in the rules.

### Likelihood Explanation
Requires: (1) Shipit tracking at least two `Repository`/`Stack` records that share a `Commit.sha` (realistic for forks/mirrors/shared-template repos, not requiring a real SHA-1 collision), and (2) the attacker being able to get a validly signed `status` webhook accepted for their own repository — which depends on `Shipit.github(organization: repository_owner)` recognizing that org, i.e., the attacker's repository must be under an org/installation Shipit already trusts (this is an explicit precondition of the question, not something the attacker can freely manufacture against an arbitrary unrelated org). Given those preconditions, the attack is fully repeatable: any CI/status event on the shared `sha` (or one manually POSTed once the attacker's own repo is a legitimate, trusted webhook source) reliably triggers the cross-repository write, with no additional attacker privilege needed beyond controlling their own repo's CI/webhook traffic.

### Recommendation
Scope `StatusHandler#process` to the repository asserted in the payload, e.g., restrict the lookup to commits belonging to `stacks` (or their `commits` association) instead of a bare `Commit.where(sha:)`:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or equivalently join through `Stack`/`Repository` via `stacks.joins(:commits).where(shipit_commits: { sha: params.sha })`, ensuring only commits under the repository named in `payload['repository']['full_name']` are mutated.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process only updates commits belonging to the repository named in the payload" do
  repo_a = shipit_repositories(:shipit) # owns stack_a
  repo_b = create_repository(owner: 'other-owner', name: 'other-repo') # distinct full_name
  stack_b = create_stack(repository: repo_b)

  shared_sha = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
  commit_a = stack_a.commits.create!(sha: shared_sha, ...)
  commit_b = stack_b.commits.create!(sha: shared_sha, ...)

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'repository' => { 'full_name' => repo_a.full_name }
  }

  assert_difference -> { commit_b.statuses.count }, 0 do
    Shipit::Webhooks::Handlers::StatusHandler.new(payload).process
  end
  # Currently FAILS: commit_b (under repo_b, not named in payload) receives a Status too,
  # proving StatusHandler#stacks (scoped to repo_a) != the actual set of mutated commits.
end
```
This demonstrates the binding `Handler#stacks(repo_a) == { commits actually mutated }` is false: `commit_b`, under `repo_b`, is mutated even though the payload names only `repo_a`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L19-24)
```ruby
        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```
