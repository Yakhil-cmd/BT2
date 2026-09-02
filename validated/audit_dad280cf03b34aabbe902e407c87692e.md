### Title
Cross-repository commit-status forgery via unscoped `Commit.where(sha:)` in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` authenticates a webhook by matching the HMAC signature against the GitHub App/organization derived from the payload's `repository.owner.login` (or `organization.login`). [1](#0-0)  That authentication proves only that *some organization's* webhook secret produced this payload — it says nothing about which repository/stack the event is allowed to mutate. `StatusHandler`, which processes GitHub `status` events, never re-checks that binding: it looks up commits globally by SHA across the entire Shipit installation and writes a `Status` to every match, ignoring the payload's `repository` field entirely.

### Finding Description
The base `Handler` class provides a `stacks` helper that correctly scopes work to the repository named in the payload: [2](#0-1) 

`CheckSuiteHandler` uses this scoping correctly: [3](#0-2) 

`StatusHandler`, however, bypasses `stacks`/`repository_name` entirely and queries `Commit` globally by SHA: [4](#0-3) 

Because `Commit` records are content-addressed by git SHA and multiple `Stack`/`Repository` records in the same Shipit instance can (and commonly do, e.g. forks, cherry-picks, shared vendor/base history) contain byte-identical commit objects with the same SHA, this handler creates a status for **every commit in every stack that happens to share that SHA**, regardless of which repository/organization actually authenticated the webhook. `Commit#create_status_from_github!` then writes the forged status and can trigger continuous delivery scheduling: [5](#0-4) 

This breaks exactly the binding called out in scope: **"an organization that authenticated versus the repository that is written."** A webhook correctly signed for Organization A's repository can write a commit status onto a commit belonging to Organization B's stack, as long as that commit's SHA also exists there.

### Impact Explanation
A forged/successful commit status can satisfy `ci.require`/`ci.blocking` checks used by `DeploySpec#required_statuses` and `Commit#deployable?`, enabling `stack.schedule_continuous_delivery` or unblocking a gated manual deploy in a stack the attacker has no legitimate relationship to. This is a cross-repository write and can lead to an unauthorized deploy of another organization's stack — matching the Critical impact bucket ("cross-repository writes ... or an unauthorized deploy").

### Likelihood Explanation
The attacker only needs legitimate access to a repository/org that Shipit's GitHub App is already installed on (their own tracked stack) and a commit whose SHA collides with one in the victim stack — trivially achievable via forks, shared base commits, or cherry-picks, which is common in real-world repository graphs. No GitHub App private key, webhook secret, ApiClient token, or write access to the victim repository is required; only a normal, signed `status` webhook for the attacker's own repo/commit is needed. The bug is a straightforward missing-scope defect, directly contrastable with the sibling `CheckSuiteHandler` which does it correctly.

### Recommendation
Scope `StatusHandler#process` the same way `CheckSuiteHandler` does: resolve `stacks` from `repository_name` in the payload and restrict the `Commit` lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalent `Commit.where(sha: params.sha, stack: stacks)`), rather than querying `Commit` unscoped.

### Proof of Concept
1. Attacker controls (or has push access to) `attacker-org/repo-a`, which is tracked as a Shipit stack under an org whose GitHub App/webhook secret is configured in this Shipit instance.
2. Victim's `victim-org/repo-b` is tracked as a different stack in the same Shipit instance, and its `main` branch contains a commit `C` whose SHA is shared with `attacker-org/repo-a` (e.g., a common ancestor commit, a cherry-picked/rebased commit, or forked history) and which is required to reach `success` CI state before deploy per `ci.require`/`ci.blocking` in its `shipit.yml`.
3. Attacker triggers (or fabricates via their own CI integration) a genuine, correctly-signed GitHub `status` webhook for `attacker-org/repo-a` reporting `sha: C, state: "success", context: "<required-context>"`.
4. Shipit's `WebhooksController#verify_signature` verifies the HMAC against `attacker-org`'s (legitimately known) webhook secret and passes. [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: C)`, matching the commit in `victim-org/repo-b`'s stack too, and calls `create_status_from_github!`, writing a `success` status onto it. [4](#0-3) 
6. `victim-org/repo-b`'s stack now considers commit `C` deployable/CI-passing, potentially firing continuous deployment or letting an attacker/insider bypass the CI gate for an unauthorized deploy.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/commit.rb (L365-386)
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
