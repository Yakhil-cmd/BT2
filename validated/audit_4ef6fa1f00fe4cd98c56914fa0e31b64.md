### Title
`StatusHandler#process` writes a `Status` to any `Commit` sharing a `sha` without verifying the webhook's `repository.full_name` matches the commit's `Stack#repository` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target commits purely by `Commit.where(sha: params.sha)`, with no join or check against the webhook payload's `repository.full_name`. Because git commit SHAs are stable across forks (a fork shares identical SHAs for every commit it hasn't diverged from), a valid, GitHub-signed `status` event fired from any repository the attacker controls (which has the Shipit GitHub App installed) can write a `Status` row against a `Commit` that belongs to a completely different `Stack`/`Repository`, including `victim/prod`.

### Finding Description
The binding the code should enforce is: `payload['repository']['full_name'] == commit.stack.repository.full_name` for every `Commit` a status is applied to. This binding is never checked.

`StatusHandler#process` is: [1](#0-0) 

It iterates `Commit.where(sha: params.sha)` - a query scoped only by `sha`, across the entire `commits` table, spanning every `Stack`/`Repository` in the Shipit instance - and calls `commit.create_status_from_github!(params)` on each match, unconditionally. The base `Handler` class already exposes `repository_name` (derived from `payload.dig('repository', 'full_name')`) and a `stacks` helper that scopes to `Repository.from_github_repo_name(repository_name)`, intended for exactly this kind of authorization check: [2](#0-1) 

`StatusHandler` never uses either helper, so the repository named in the incoming webhook is completely disconnected from which `Stack`'s commits get the forged status.

`Commit#create_status_from_github!` writes the row unconditionally: [3](#0-2) 

Downstream, `Commit#deployable?` and `Commit#status` (hence `success?`) are derived purely from these `statuses`/`check_runs` rows: [4](#0-3) [5](#0-4) 

`Stack#trigger_continuous_delivery` then picks `next_commit_to_deploy`, filters via `deployable_commits`/`Commit#deployable?`, and - if `should_resume_continuous_delivery?` and `should_delay_continuous_delivery?` both return false - calls `trigger_deploy`: [6](#0-5) [7](#0-6) 

`should_delay_continuous_delivery?`'s first clause, `commit.deploy_failed?`, and the `checks?` clause both depend on data the attacker never touches; they do not gate on the forged `Status` unless the stack has no `deployment_checks` and no `checks?` gating (as stated in the preconditions), in which case the forged `success` status flows straight through `Commit#deployable?` into `trigger_deploy`.

**Exploit flow**: the attacker forks/owns a repository (`attacker/repo`) sharing commit history with `victim/prod` (e.g., a fork of the upstream repo, prior to divergence) which has the Shipit GitHub App installed (so GitHub will produce a validly-signed webhook for events on it). The attacker triggers a `status` event on `attacker/repo` for a commit SHA that is also present, undeployed, in `victim/prod`'s `commits` table (a shared ancestor commit). GitHub signs and delivers this webhook normally - no forged signature is needed since it's a real, GitHub-originated event for a repo the attacker legitimately controls. `StatusHandler#process` matches by `sha` alone and writes a `success` `Status` scoped to `victim/prod`'s `Commit`, satisfying `Commit#deployable?` for `victim/prod` and triggering an unauthorized deploy.

Existing guards do not catch this: signature verification (`verify_signature`) only proves the webhook came from GitHub for *some* repo the App is installed on - it says nothing about which repo the payload names, and `StatusHandler` never checks that field against the commit it mutates.

### Impact Explanation
A forged/misattributed `success` status written for `victim/prod`'s pending commit lets `Stack#trigger_continuous_delivery` proceed to `trigger_deploy`, spawning a real `Deploy` `Task` (and hence `Command`/`PTY.spawn`) against `victim/prod`'s deploy host - an unauthorized deploy triggered by a webhook that authenticates a different repository. This matches the "unauthorized deploy" and "payload for one repository mutating another's stack/commit" Critical categories. Repeatable for any `Stack` whose commits share SHAs with a repository the attacker controls (forks, mirrors, or repos with common ancestry) as long as its continuous-delivery config lacks `deployment_checks?`/`checks?` gating strong enough to block the forged status alone.

### Likelihood Explanation
Requires: (1) attacker controls a GitHub repository with the Shipit GitHub App installed (so a genuinely GitHub-signed webhook is deliverable), (2) that repository shares a commit SHA with an undeployed commit on `victim/prod` (trivially true for forks prior to divergence, or achievable via timing a fork right after an upstream push), (3) `victim/prod`'s `continuous_deployment: true` and its `should_delay_continuous_delivery?`/`should_resume_continuous_delivery?` gates (`checks?`, `deployment_checks?`, `deploy_failed?`, `recently_pushed?`) don't independently block. Attacker cost is low (own a fork, trigger any CI/status webhook); no secrets needed since the signature check is satisfied by GitHub itself for the attacker's own repo.

### Recommendation
In `StatusHandler#process` (and any other sha-keyed handler), scope the commit lookup through the webhook's own repository, e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently `Commit.joins(:stack => :repository).where(sha: params.sha, repositories: { owner: ..., name: ... })`, using the existing `Handler#repository_name`/`stacks` helper, rather than a bare cross-tenant `Commit.where(sha:)`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` style, adjusted per repo layout constraints - out-of-scope paths excluded from being modified, but this is the shape a Devin session should add):
```ruby
victim_stack = shipit_stacks(:victim_prod) # continuous_deployment: true, no deployment_checks/checks configured
shared_sha = "deadbeef" * 5
victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)

attacker_repo_payload = {
  'sha' => shared_sha,
  'state' => 'success',
  'context' => 'ci/attacker',
  'repository' => { 'full_name' => 'attacker/repo' } # different from victim_stack.repository.full_name
}

assert_difference('victim_stack.deploys.count') do
  Shipit::Webhooks::Handlers::StatusHandler.call(attacker_repo_payload)
  victim_stack.trigger_continuous_delivery
end

assert_equal 'attacker/repo', attacker_repo_payload['repository']['full_name']
refute_equal victim_stack.repository.full_name, attacker_repo_payload['repository']['full_name']
assert victim_commit.reload.success?
```
Both sides of the binding (`payload['repository']['full_name']` vs `victim_commit.stack.repository.full_name`) are asserted unequal, yet the deploy count increments, proving the divergence.

### Citations

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L219-229)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

**File:** app/models/shipit/stack.rb (L701-713)
```ruby
    def should_resume_continuous_delivery?(commit)
      (deployment_checks_passed? && !deployable?) ||
        deployed_too_recently? ||
        commit.nil? ||
        commit.deployed?
    end

    def should_delay_continuous_delivery?(commit)
      commit.deploy_failed? ||
        (checks? && !EphemeralCommitChecks.new(commit).run.success?) ||
        !deployment_checks_passed? ||
        commit.recently_pushed?
    end
```
