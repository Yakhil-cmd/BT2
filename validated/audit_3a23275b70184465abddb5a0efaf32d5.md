### Title
Cross-repo commit status forgery flips `Commit#deployable?` and triggers unauthorized continuous deployment - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits purely by `sha`, with no check that the webhook's authenticated `repository.full_name` matches the repository owning the stack the commit belongs to. Any GitHub user who can get a validly-signed status webhook delivered for a commit sha that also exists in a victim's tracked repository (e.g., via a public fork sharing commit objects) can flip that commit's CI status to `success`, making `Commit#deployable?` return `true` and causing `Stack#trigger_continuous_delivery` to ship an unreviewed/failing commit to production.

### Finding Description
The broken binding is: `payload.repository.full_name` (the repo whose webhook signature was verified in `WebhooksController#verify_signature`) **==** the repository that owns the `Stack` of the `Commit` being mutated (`commit.stack.repository`). This equality is never checked.

`WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) only proves the payload was signed by GitHub for the organization named in `payload.dig('repository','owner','login')` — i.e., it authenticates *who sent the event*, not *which stack the event is allowed to affect*.

Other handlers correctly scope by repository via `Handler#stacks`: [1](#0-0) 

But `StatusHandler#process` bypasses this entirely and queries commits system-wide by sha only: [2](#0-1) 

`Commit#create_status_from_github!` then attributes the forged status to the commit's *real* `stack_id` (the victim's stack), not the attacker's repo: [3](#0-2) [4](#0-3) 

Because `Status belongs_to :stack` and `Commit#status` aggregates statuses/check_runs by that `stack_id`, the forged `success` status is indistinguishable from a legitimate one for `deployable?`: [5](#0-4) 

`add_status` then fires `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges` on the state transition: [6](#0-5) 

**Exploit flow**: Attacker forks the victim's public repository (git commit objects/SHAs are identical across forks), obtaining a repo they own that contains an existing commit whose sha matches a pending/failing commit already tracked by the victim's Shipit stack. Attacker calls the GitHub Statuses API on their own fork for that sha with `state: success` and a `context` matching the victim stack's required status context. GitHub delivers a webhook to Shipit signed for the attacker's own repo/org — this passes `verify_signature` legitimately, since it truthfully is a webhook from a repo the attacker controls. `StatusHandler#process` then does `Commit.where(sha: params.sha)`, which matches the victim's commit row (same sha, different repo/stack), and calls `create_status_from_github!` on it, writing a `success` `Status` scoped to the victim's `stack_id`. On the next `ContinuousDeliveryJob` tick, `Stack#trigger_continuous_delivery` → `next_commit_to_deploy` → `deployable_commits` sees `commit.deployable?` as `true` and deploys.

None of the listed guards prevent this: `verify_signature` authenticates the sender's own repository, not the target stack; `drop_unhandled_event` doesn't filter by repo; there is no `ExplicitParameters` schema check on `repository.full_name` for `StatusHandler`; `force_github_authentication`, `User#authorized?`, `require_permission!`, and the `stacks` scope are irrelevant to unauthenticated webhook ingestion; model validations on `Status`/`Commit` do not check repository ownership.

### Impact Explanation
An attacker who owns any repository (including a public fork of the victim's repo) can write a `Status` record for a commit belonging to a stack/repository they do not own and do not control, causing `Commit#deployable?` to flip to `true` and `Stack#trigger_continuous_delivery`/`trigger_deploy` to ship that commit — an unauthorized deploy of a commit whose real CI is pending or failing. This is repeatable against any victim stack whose tracked commit sha is discoverable/obtainable by the attacker (trivial for any public GitHub repo via forking), and the blast radius spans every stack/tenant hosted on the same Shipit instance, since the vulnerable lookup (`Commit.where(sha:)`) is completely repository-agnostic. This matches the Critical category: "an unauthorized deploy" caused by "a payload for one repository mutating another's stack/commit."

### Likelihood Explanation
Preconditions required: victim stack has `continuous_deployment: true`, an undeployed commit currently pending/failing, and a `DeploySpec` required status `context` name the attacker can guess or read (context names are typically well-known CI check names, e.g., `ci/circleci`, and are visible on the victim's own commit status UI/PRs). The attacker needs only: (1) their own GitHub account, (2) a repo they control containing the target commit object (achievable by simply forking the public victim repo), and (3) the ability to POST a commit status via the GitHub API for their own repo (standard, unprivileged GitHub permission for any repo they own). No Shipit credentials, API tokens, or `webhook_secret` are required. This is low-cost and fully repeatable/scriptable against any publicly-forkable repo tracked by a continuous-deployment-enabled Shipit stack.

### Recommendation
In `StatusHandler#process`, scope the commit lookup by both `sha` and the authenticated `repository_name` from the payload, mirroring `Handler#stacks`/`repository_name`, e.g., restrict to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` (or equivalently verify `commit.stack.repository == Repository.from_github_repo_name(repository_name)` before calling `create_status_from_github!`), rejecting/ignoring statuses whose payload repository does not match the commit's own stack repository.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, or `test/models/commits_test.rb`, purely as illustration of the assertions — actual file omitted per scope rules):
1. Create `victim_repo` (`owner/victim`) and `attacker_repo` (`owner/attacker`), each with its own `Stack` (`continuous_deployment: true` for `victim_stack`).
2. Create `commit = Commit.create!(stack: victim_stack, sha: "deadbeef"*5)` — simulating a commit shared across the two repos' git history (same sha, different owning stack).
3. Assert baseline: `commit.deployable?` is `false` (no successful status yet) — i.e., `commit.stack.repository == victim_repo` while no status exists tied to `attacker_repo`.
4. Build a status webhook payload with `repository.full_name == "owner/attacker"`, `sha == commit.sha`, `state == "success"`, `context` matching victim's required context, and call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing controller-level signature verification, which is presumed valid since attacker legitimately owns `attacker_repo`).
5. Assert `commit.reload.deployable?` is now `true`, and `Status.where(stack_id: victim_stack.id, commit_id: commit.id).last.state == "success"` even though `payload['repository']['full_name'] != victim_stack.repository.full_name` — proving the equality claimed as the binding (`payload repo == commit's stack repo`) is false yet the mutation succeeded.
6. Stub `ContinuousDeliveryJob#perform` (or call `victim_stack.trigger_continuous_delivery` directly) and assert `Stack#trigger_deploy` is invoked with the forged-success commit, confirming the unauthorized-deploy impact.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
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
