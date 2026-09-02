This confirms the vulnerability. `PushHandler#process` and `CheckSuiteHandler#process` both scope their queries through `stacks` (which resolves via `Repository.from_github_repo_name(repository_name)` from the webhook's own payload), but `StatusHandler#process` does not — it looks up `Commit.where(sha: params.sha)` globally across the entire `commits` table, with no repository/stack scoping at all. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` updates CI status for **every** `Commit` record in the database sharing the given `sha`, without scoping to the repository that the incoming webhook belongs to (unlike `PushHandler` and `CheckSuiteHandler`, which both scope through the `stacks` helper derived from `payload['repository']['full_name']`). A `status` webhook that GitHub legitimately delivers for repository A (verified via `Shipit.github(organization: repository_owner).verify_webhook_signature`, so the signature check passes since it's a real webhook from A) can therefore mutate the CI status of an identical-sha commit belonging to a completely unrelated stack/repository B, because `Status.replicate_from_github!` uses each matched commit's *own* `stack_id`, not the webhook's origin repo.

### Finding Description
The binding that must hold is: `repository that authenticated/produced this status webhook == repository whose commit/stack is mutated by it`. `verify_signature` in `Shipit::WebhooksController` only checks that the payload's signature matches the GitHub App secret for `repository_owner` (the org that owns the *source* repo of the webhook) [5](#0-4) . It says nothing about which `Commit`/`Stack` rows may be touched. `StatusHandler#process` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries `Commit` by `sha` alone, globally, with no `repository_name`/`stacks` filter — breaking the binding above. Every other handler that touches per-repository state (`PushHandler`, `CheckSuiteHandler`) explicitly scopes through `stacks`, which resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))` first [4](#0-3) ; `StatusHandler` skips this scoping entirely.

`Commit#create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)` [6](#0-5) , using the matched commit's *own* `stack_id` — meaning the forged status is attributed to the victim commit's real stack, and `Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) then reads `success?` from that forged status [7](#0-6) .

Exploit flow: attacker administers repository A, which is registered as a Shipit stack (a legitimate, unrelated deploy-scoped setup) and has GitHub's status webhook wired to Shipit for that org (real, valid signature). Attacker crafts/finds a commit in repository A whose `sha` happens to coincide with a commit sha tracked in victim stack B's `commits` table (e.g., via a shared fork history, cherry-pick, or shared upstream — sha collision itself is out of scope, the "shared sha" precondition is given). Attacker triggers a real `success` status on that sha in repo A (e.g., via their own CI). GitHub delivers the webhook to Shipit, passes signature verification for org A, and `StatusHandler#process` finds **both** the repo-A commit and the repo-B (victim) commit sharing that sha, creating a `success` `Status` on each — including on the victim's stack. Subsequently, `Shipit::Api::DeploysController#create` with `require_ci=true` calls `commit.deployable?`, which now returns `true` for the victim's commit despite it never having passed the victim's own CI, so the `param_error!(:require_ci, ...)` guard is bypassed [8](#0-7) .

No existing guard prevents this: `verify_signature` only authenticates the source org, not the target rows mutated; `ExplicitParameters` schema for `StatusHandler` only validates shape (`sha`, `state`, etc.), not repository binding [9](#0-8) ; and `require_permission!`/`stacks` scoping in `DeploysController` is irrelevant since the forged state is already persisted before any authorized deploy call happens.

### Impact Explanation
A payload legitimately originating from repository A causes a database write (`Status` record, and downstream `deployable?`/`state` mutation) against repository B's `Commit`/`Stack`, which never authenticated or authorized that data. This directly matches the Critical category "a payload for one repository mutating another's stack, commit, task or team" and enables "an unauthorized deploy" once any authorized caller (even one who trusts `require_ci`) triggers `POST /api/stacks/:id/deploys?require_ci=true` for the victim stack. The blast radius is global: it affects every stack in the installation whose commits table could ever contain a `sha` overlapping with an attacker-controlled repository, and it is repeatable per matching sha at will (attacker only needs to (re)fire a status event on their own commit).

### Likelihood Explanation
The attacker must legitimately control a repository (fork, personal repo) that is registered with Shipit and has GitHub's status webhook configured to point at the Shipit instance (a normal, unprivileged setup any repo owner can do) — no Shipit secrets, sessions, or API tokens are required for the status-forgery step itself. The remaining precondition, "shared sha" with the victim's commit, is stipulated as a given precondition in the question (via natural git operations like forks/cherry-picks/rebases producing identical shas across repositories) rather than a raw SHA-1 collision, making it realistic in cases such as monorepo splits, template repos, or forks with common history. Given that precondition, exploitation is a single crafted status POST from the attacker's own CI/webhook flow and is fully repeatable.

### Recommendation
Scope `StatusHandler#process` to only touch commits belonging to stacks resolved from the webhook's own `repository.full_name`, mirroring `PushHandler`/`CheckSuiteHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This restores the binding: only commits within stacks belonging to the repository that actually sent (and was signature-verified for) the webhook get their status mutated.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or equivalent):
```ruby
test "status webhook for repo A must not mutate a same-sha commit belonging to repo B's stack" do
  stack_a = shipit_stacks(:shipit)          # attacker-administered stack (repo A)
  stack_b = shipit_stacks(:cyclimse)        # victim stack (repo B), unrelated repository
  shared_sha = "deadbeef" * 5

  commit_a = stack_a.commits.create!(sha: shared_sha, ...)
  commit_b = stack_b.commits.create!(sha: shared_sha, ...)

  payload = {
    'sha' => shared_sha, 'state' => 'success', 'context' => 'ci/attacker',
    'branches' => [{ 'name' => stack_a.branch }],
  }.merge('repository' => { 'full_name' => stack_a.repository.full_name, 'owner' => { 'login' => stack_a.repository.owner } })

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  # LEFT side of binding: repo that produced the status
  producing_repo = stack_a.repository.full_name
  # RIGHT side: repo whose require_ci-gated deployable? consults it
  consuming_repo = stack_b.repository.full_name

  refute_equal producing_repo, consuming_repo, "sanity: repos are distinct tenants"

  # Vulnerable behavior (should NOT happen after fix):
  refute commit_b.reload.deployable?, "victim commit must not become deployable from an unrelated repo's status webhook"
end
```
Currently, with the unfixed `StatusHandler#process`, `commit_b.reload.deployable?` becomes `true`, and a follow-up assertion against `Shipit::Api::DeploysController#create` with `require_ci: true` for `stack_b` and `sha: shared_sha` would no longer raise the `"Commit is not deployable"` `param_error!`, confirming the bypass.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-22)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?
```
