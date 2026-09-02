### Title
Cross-repository status mutation via global `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits by SHA alone, across the entire `commits` table, with no scoping to the repository that produced the webhook. Since a git SHA is a property of commit content, not of the reporting repository, a commit shared between a victim's tracked repository and any other repository (e.g., a fork, or independently pushed identical commit) will be mutated by a status event sent from the unrelated repository.

### Finding Description
The binding the code implicitly assumes is: `commit.stack.repository == repository_owner(payload)` for every `commit` returned by `Commit.where(sha: params.sha)`. This does not hold, because SHA is derived purely from tree/parent/author/committer/message content, not from which repository holds the object. Two independent repositories (a public upstream and any of its many forks, including one owned by the attacker) can contain a git commit object with an identical SHA whenever the attacker's fork shares commit history with the tracked upstream (the common and unavoidable case for any fork prior to divergence).

Code path: `Shipit::WebhooksController#create` dispatches every incoming, signature-verified webhook event to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [1](#0-0) . Signature verification only checks that the payload was signed for the org named in `payload['repository']['owner']['login']` [2](#0-1)  — it authenticates that a real GitHub webhook was sent by a repository the app is installed on, but places no constraint on which SHAs that webhook is allowed to reference.

`StatusHandler#process` then does:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 

This is unlike every other handler in the same directory. `PushHandler`, `CheckSuiteHandler`, and the `pull_request/*` handlers all resolve records through the base class's `stacks` scope, which restricts to `Repository.from_github_repo_name(repository_name)&.stacks` [4](#0-3) . `StatusHandler` never calls `stacks` or filters by `repository_name`/`payload.dig('repository', 'full_name')` at all — the base class's own repository-scoping helper exists but is unused here.

Attack flow: The Shipit GitHub App (or equivalent webhook integration) is installed on the attacker's own repository (a fork of, or a repo sharing history with, a victim's Shipit-tracked repository). The attacker triggers a real, validly signed `status` event from GitHub referencing a commit SHA that also exists as a `Commit` row under the victim's `Stack` (created because the victim's Shipit instance already ingested that same commit via its own push/PR history, which is common for shared ancestor commits or intentionally identical duplicated commits in a fork). `Commit.where(sha: params.sha)` returns both the attacker-owned commit row and the victim's commit row (if both exist), and `create_status_from_github!` is invoked on all of them — including the victim's, whose `stack` the attacker never authenticated against. This can flip the victim commit's CI `state` to `success`, which feeds `deployable?`/`blocked?`/`schedule_continuous_delivery` [5](#0-4) [6](#0-5) , potentially causing an unauthorized deploy to proceed on the victim's stack when combined with continuous deployment settings.

No existing guard prevents this: `verify_signature` only authenticates the sending org/repo, not the SHA scope; `ExplicitParameters` only validates payload shape; there is no `Repository`/`Stack` ownership check anywhere in `StatusHandler`.

### Impact Explanation
A successful request from an attacker-controlled, app-installed repository can write a fabricated CI status onto a victim's commit row that the attacker's repository never legitimately authenticated. This can unblock `deployable?` checks and trigger `schedule_continuous_delivery`, potentially causing an unauthorized deploy on the victim's stack — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy". The attack is repeatable against any repository that shares commit history (a common fork relationship) with a repository the attacker controls and can install the webhook integration on.

### Likelihood Explanation
Preconditions: the attacker needs the ability to have the app/webhook installed on a repository they control (typical for public-repo forks with GitHub Apps installable by any user), and needs a real matching SHA present in the victim's `commits` table — which naturally occurs for shared ancestor commits of forks, or trivially for repositories that intentionally track the exact same upstream commit history. No Shipit secrets, sessions, or API tokens are required; the request is a normal, validly signed GitHub webhook from the attacker's own installation. This makes the exploit low-cost and highly feasible for any forked-repository scenario, and repeatable per matching commit.

### Recommendation
Scope `StatusHandler#process` to the reporting repository, mirroring `PushHandler`/`CheckSuiteHandler`: query `stacks.flat_map(&:commits).where(sha: params.sha)` (or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`) instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook from one repository must not mutate another repository's commit sharing the same sha" do
  victim_stack = shipit_stacks(:shipit)
  attacker_stack = create_stack(repository: create_repository(owner: 'attacker', name: 'fork'))

  shared_sha = 'a' * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'shared ancestor commit')
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: 'shared ancestor commit')

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => attacker_stack.repository.full_name, 'owner' => { 'login' => 'attacker' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  victim_commit.reload
  attacker_commit.reload

  assert_equal 'success', attacker_commit.status.state # expected, attacker's own commit
  refute_equal 'success', victim_commit.status.state    # currently FAILS: victim commit also mutated
end
```
This demonstrates that `Commit.where(sha:)` in `StatusHandler` is not scoped to the reporting repository's stacks, so a status event legitimately signed for the attacker's repository mutates a commit belonging to an unrelated victim stack purely because the SHA matches.

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
