### Title
`security/scan` status webhook flips CI state for any commit sharing that SHA, regardless of which repository authenticated the webhook - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely by `sha`, without scoping to the repository named in the webhook payload, unlike the base `Handler` class which provides a `stacks`/`repository_name`-scoped lookup helper. Any commit whose SHA is shared across repositories (e.g. via a fork sharing history with a victim repo, both covered by the same GitHub App/organization installation) will have its status updated even though the webhook was authenticated only for the attacker's own repository.

### Finding Description
The broken binding is: `status webhook.repository.full_name == commit.stack.repository.full_name` is expected to hold before `commit.create_status_from_github!` is invoked, but the code never checks it.

`StatusHandler#process` does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [1](#0-0) 

This iterates over **every** `Commit` record in the database matching the raw SHA, across all stacks/repositories, with no filter on `stack.repository`. Compare this to the base `Handler` class, which defines a `stacks`/`repository_name` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) intended to scope work to the repository named in `payload['repository']['full_name']` [2](#0-1) , but `StatusHandler` does not use it at all.

`Commit#create_status_from_github!` writes the status and then `add_status` fires `stack.schedule_merges` and hooks based on the new state [3](#0-2) [4](#0-3) , which is exactly the CI-state signal that gates `Commit#deployable?`/`#blocked?` and thus continuous delivery/merge decisions [5](#0-4) .

Webhook authentication (`verify_signature`) is scoped by GitHub organization, not by repository:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(...)
``` [6](#0-5) 
Signature verification proves the request came from GitHub for *some* repository owned by that organization/app installation — it does not prove the payload's SHA "belongs" to the specific stack it is applied to. Since `StatusHandler` never checks `payload['repository']['full_name']` against the commit's stack repository, a genuinely-signed status webhook for the attacker's own repository (in the same org/installation) whose SHA happens to coincide with a commit SHA recorded in a victim's stack (e.g. because the attacker's repo is a fork sharing commit history with the victim repo) will update the victim commit's CI status.

None of the listed guards prevent this: `verify_signature` only checks the organization-level HMAC, `ExplicitParameters` only validates parameter shapes (`sha`/`state`/`context` types), and there is no repository/stack ownership check anywhere in `StatusHandler` or `Commit.create_status_from_github!`.

### Impact Explanation
An attacker who can generate a legitimately-signed status webhook for a repository they control (with a SHA that matches a commit also tracked by a victim's stack) can inject a passing (or failing) `security/scan` status onto that commit in the victim's stack. If that stack is configured as `production environment` and requires `security/scan` as a required status, this can unblock a deploy/merge that should have been blocked, or block a legitimate deploy — an unauthorized deploy/merge/rollback impact, matching the "payload for one repository mutating another's ... commit" Critical category. The blast radius spans any stack whose repository shares commit history (forks, mirrors, or otherwise identical SHAs) with a repository under an attacker's control within the same GitHub App/org installation, and is repeatable for any commit/context.

### Likelihood Explanation
Exploitation requires: (1) an attacker-controlled repository covered by the same GitHub App/organization installation Shipit trusts (so `verify_signature` passes), and (2) a commit SHA that is shared between that repository and a targeted victim stack's repository — realistically achievable when the attacker's repo is a fork of, or shares history with, the victim's repo. This does not require any Shipit secret, session, or API token — only the ability to produce a validly-signed GitHub status webhook for a repo the attacker controls. The precondition of SHA-sharing across repos narrows applicability somewhat but is a well-known and common scenario (forks retain identical commit SHAs for shared history).

### Recommendation
Scope `StatusHandler#process` to only update commits belonging to stacks whose repository matches `payload['repository']['full_name']`, using the existing `stacks` helper from the base `Handler` class (e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or filter `Commit.where(sha: params.sha)` by `stack: stacks`) instead of a bare global `Commit.where(sha:)` lookup.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `stack_victim` with `repository` `victim/repo`, `environment: 'production'`, and `required_statuses = ['security/scan']`.
2. Create `commit = stack_victim.commits.create!(sha: 'a'*40, ...)` with no prior `security/scan` status (so `deployable?` is currently false / blocked).
3. Create a second, unrelated `stack_attacker` with `repository` `attacker/repo` (different repository, simulating a fork sharing the same SHA), and a `commit` record with the same `sha`.
4. Build `payload = { 'sha' => 'a'*40, 'state' => 'success', 'context' => 'security/scan', 'repository' => { 'full_name' => 'attacker/repo', 'owner' => { 'login' => 'attacker' } } }`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
6. Assert: `commit.reload.status.state == 'success'` on the **victim** commit even though the webhook's `payload['repository']['full_name']` was `attacker/repo`, i.e. assert `stack_victim.commits.find_by(sha: 'a'*40).success? == true` while `stack_victim.github_repo_name != payload['repository']['full_name']` — proving the equality `webhook.repository.full_name == commit.stack.repository.full_name` was never enforced and the victim's production stack `deployable?` flips from `false` to `true` as a result.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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
