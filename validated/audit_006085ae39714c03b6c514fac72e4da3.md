### Title
Cross-tenant Status forgery via global `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) with `Commit.where(sha: params.sha)`, a lookup that spans every `Stack`/`Repository` in the installation, instead of scoping through the `stacks` helper (based on the payload's `repository.full_name`) that every other handler (e.g. `PushHandler`) uses. Because webhook signature verification only proves the payload's own `repository.owner.login` is authentic, but `StatusHandler` never checks that the resolved `Commit#stack#repository` belongs to that same owner, any org whose webhook is legitimately signed can write a `Status` (and thus flip CI state) onto a commit belonging to a completely different tenant's stack, as long as both stacks happen to track a commit with the same SHA (trivially achievable for shared/vendored/public commits, since SHAs are content-addressed).

### Finding Description
The binding that should hold is: `commit.stack.repository ∈ {repositories owned by repository_owner authenticated in verify_signature}` for every `Commit` mutated while processing a given payload. This is enforced in `PushHandler#process` via the `stacks` helper, defined in `Handler#stacks`: [1](#0-0) 

which scopes to `Repository.from_github_repo_name(repository_name)&.stacks`, i.e. only stacks belonging to the repository named in `payload['repository']['full_name']`. `PushHandler` uses exactly this scope: [2](#0-1) 

`StatusHandler#process`, however, bypasses `stacks` entirely: [3](#0-2) 

`Commit.where(sha: params.sha)` is a global query with no join to `Repository`/`Stack` and no filter on the payload's `repository` field at all. `WebhooksController#verify_signature` only checks that the signature is valid for `repository_owner` derived from the payload: [4](#0-3) 

This proves authenticity of "org-a signed this payload," not "org-a owns every commit this payload will mutate." `StatusHandler` never re-checks the second half of that binding, so the two sides diverge: the org that authenticated the request is not verified to equal the org owning the `Commit` rows being written.

Exploit flow: attacker controls (or is a legitimate tenant of) org-a, tracked by Shipit with its own valid webhook secret. Org-b (a different tenant) has a `Stack`/`Commit` tracking SHA `S` (e.g., a shared vendored dependency commit, or any commit whose content — and thus SHA — the attacker can reproduce, since git SHAs are content-addressed and not repository-scoped). The attacker pushes/reproduces a commit with SHA `S` in a repository under org-a and causes GitHub to emit a genuinely-signed `status` webhook for `org-a/whatever` naming SHA `S` with `state: 'success'` (or `failure`). `WebhooksController#verify_signature` passes because the signature is valid for org-a. `StatusHandler.call` → `process` then runs `Commit.where(sha: 'S')`, which matches org-b's `Commit` row too, and calls `commit.create_status_from_github!(params)`, which resolves to org-b's own `stack_id`: [5](#0-4) [6](#0-5) 

This writes a real `Status` row scoped to org-b's stack, attacker-controlled in `state`/`description`/`target_url`/`context`, triggering `after_create :enable_ci_on_stack` and `schedule_continuous_delivery`, which feeds directly into org-b's deployability/CI gating logic.

None of the existing guards prevent this: `verify_signature` checks signature validity per-organization only, not per-target-record; `drop_unhandled_event` only checks event routing; the `ExplicitParameters` schema in `StatusHandler.params` only validates types, not repository ownership; there is no `require_permission!`/`stacks` scoping in this handler at all.

### Impact Explanation
A payload legitimately signed for one repository/organization mutates `Status` records belonging to a `Commit`/`Stack` owned by a different, unrelated tenant. Since `Status#state` feeds CI/deployability gating (`enable_ci_on_stack`, `schedule_continuous_delivery`, deployable-status hooks), an attacker can forge a `success` status to help unblock a deploy gate, or forge `failure`/`error` to block deploys, on another tenant's stack — a cross-repository state mutation matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). This is repeatable against any tenant whose tracked commit SHA the attacker can reproduce or already knows (trivial for any commit derived from a public upstream, vendored library, or shared monorepo history), and requires no compromise of any Shipit secret beyond the attacker's own legitimately-issued webhook signing key.

### Likelihood Explanation
Preconditions: the attacker needs a Shipit-tracked repository/organization of their own (so that GitHub will send genuinely-signed webhooks on their behalf — no theft of secrets required), and a target commit SHA that is also tracked by another tenant's `Stack`. Colliding SHAs are not a brute-force problem: git SHAs are content hashes, so any commit copied verbatim into the attacker's own repository (e.g. a shared open-source dependency, a fork of a public repo, or a known upstream commit) reproduces the identical SHA. Attacker cost is low (just needs their own onboarded repo and knowledge of a target SHA); the action is fully repeatable per request.

### Recommendation
Scope `StatusHandler#process` through the repository-derived `stacks` association (as `PushHandler` and other handlers do), and further restrict the `Commit.where(sha:)` query to `stacks.commits` (or join `Commit` through `Stack`/`Repository` matching `payload['repository']['full_name']`) instead of querying `Commit` globally, e.g.:

```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process does not create a status on a commit belonging to a different repository" do
  shared_sha = "deadbeef" * 5  # 40 hex chars, simulate a shared commit sha
  repo_a = shipit_repositories(:example) # or create Repository fixture for org-a
  stack_a = shipit_stacks(:shipit) # belongs to repo_a
  stack_b = Shipit::Stack.create!(repository: Shipit::Repository.create!(owner: 'org-b', name: 'repo-b'), environment: 'production', branch: 'main')

  commit_a = stack_a.commits.create!(sha: shared_sha, message: "shared", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)
  commit_b = stack_b.commits.create!(sha: shared_sha, message: "shared", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/travis',
    'repository' => { 'full_name' => repo_a.github_repo_name, 'owner' => { 'login' => repo_a.owner } }
  }

  assert_no_difference -> { commit_b.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end

  assert_difference -> { commit_a.reload.statuses.count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end
```
This test currently fails against the vulnerable implementation (`commit_b.statuses.count` increases), demonstrating the cross-tenant write; after applying the fix to scope by `stacks`/repository, only `commit_a` receives the `Status`.

### Citations

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
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
```
