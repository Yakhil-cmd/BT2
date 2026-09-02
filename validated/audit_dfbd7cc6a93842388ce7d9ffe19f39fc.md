### Title
Global (non-repo-scoped) commit lookup in `StatusHandler#process` lets an attacker's verified webhook write CI status onto another tenant's commit, feeding `Commit#deployable?` and triggering an unauthorized automated deploy - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit(s) with `Commit.where(sha: params.sha)` with no filter on repository/owner/stack, even though `WebhooksController#verify_signature` only proves the payload originated from *some* org the attacker controls. If a commit with the same SHA also exists under a victim stack (e.g. via a GitHub fork, which by design shares identical commit SHAs with upstream), the attacker's own, validly-signed webhook mutates the victim's `CommitStatus`, flips `Commit#deployable?` to `true`, and — if the victim stack has `continuous_deployment: true` — the next scheduled continuous-delivery pass deploys it under the victim's own `GITHUB_TOKEN`/deploy spec.

### Finding Description
The broken binding is:
`repository_owner_verified_by_signature == repository_owner(commit.stack)` — this equality is assumed but never checked.

Trace:
1. `WebhooksController#verify_signature` verifies the HMAC signature against `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the attacker-controlled JSON payload's `repository.owner.login`/`organization.login`. [1](#0-0) [2](#0-1)  This only proves the payload came from a real installation for *that* org — the attacker's own org, if they own/fork a public repo with a GitHub App/webhook configured.
2. `StatusHandler#process` never re-derives or checks `params.dig('repository', ...)` at all; it looks up commits purely by SHA across the entire `commits` table: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [3](#0-2) 
3. `create_status_from_github!` → `add_status` writes the new `Status` row and, on a state transition to `success`, fires side effects (merge scheduling, `deployable_status` hook). [4](#0-3) [5](#0-4) 
4. `Commit#deployable?` is purely a function of the (now attacker-controlled) status state: `!locked? && (stack.ignore_ci? || (success? && !blocked?))`. [6](#0-5) 
5. `Api::DeploysController#create`'s `require_ci` check and continuous-delivery logic both consult this same `deployable?` predicate, so once it flips to `true` for the victim's commit row, both manual API deploys (gated by `require_ci`) and automatic continuous-delivery passes treat the commit as deployable. [7](#0-6) 

Since a SHA is a content hash, an attacker cannot arbitrarily choose a colliding SHA against unrelated content — but forking a public victim repository (a routine, unprivileged GitHub action) produces an attacker-owned repository whose commits share *identical* SHAs with the upstream victim repository's commits by construction. Any webhook signed with the attacker's own fork's secret for that SHA will match the victim's `Commit` row via the unscoped `Commit.where(sha:)` query, because `Commit` records are keyed by `(sha, stack_id)` but the handler never filters by `stack_id`/repository.

None of the existing guards prevent this: `verify_signature` validates authenticity of the sender's own org, not ownership of the SHA/commit being referenced; `drop_unhandled_event` only filters unhandled event types; there is no `ExplicitParameters` field or model validation tying the incoming `sha`/`context`/`state` to the repository that signed the request.

### Impact Explanation
An unprivileged GitHub user who forks a public victim repository can, via their own real (but victim-independent) webhook installation, write a fabricated `success` status onto the victim's commit row. This flips `Commit#deployable?` to `true` for a commit the victim's own CI may never have approved. If the victim stack runs `continuous_deployment: true`, the next automated continuous-delivery cycle (or any operator issuing an API deploy without `require_ci` override awareness) executes `Task#run`/`Command#start` using the victim stack's own deploy spec and `GITHUB_TOKEN` — i.e., an unauthorized deploy is executed under credentials the attacker never possessed. This is repeatable against any public repository that has a corresponding Shipit-tracked fork/mirror sharing commit history, and the blast radius crosses tenant boundaries (attacker's forged data drives execution using victim's own secrets). This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team" and "an unauthorized deploy."

### Likelihood Explanation
Preconditions: the victim stack must have `continuous_deployment: true` (or an operator relies on `deployable?`/CI status without independently re-verifying); the victim's commit must exist verbatim (same SHA) in a repository the attacker controls or has forked, which is a normal and free GitHub action for any public repository. Attacker cost is low: fork the repo, ensure a webhook/app is configured for the fork (typical if the org uses a GitHub App broadly installed across the org/its forks), and send a single `status` webhook event with the shared SHA. This is fully repeatable against any tracked commit whose SHA is shared across repositories.

### Recommendation
Scope `StatusHandler#process` (and any other handler doing bare `Commit.where(sha: ...)` lookups) to only the commits belonging to stacks whose `repository` matches the verified `repository_owner`/`repository.full_name` from the signed payload, e.g. join through `Stack -> Repository` and filter by `repository.owner` and `repository.name` in addition to `sha`, rather than trusting a global SHA match.

### Proof of Concept
Minitest plan (no live GitHub):
1. Create two stacks/repos, `stack_a` (attacker-owned org) and `stack_b` (victim org), each with a `Commit` record sharing the identical `sha` (simulating a fork).
2. Set `stack_b.update!(continuous_deployment: true)`.
3. Ensure `stack_b`'s commit currently has no successful status (`refute commit_b.deployable?`).
4. Invoke `Shipit::Webhooks::Handlers::StatusHandler.new.call(params_signed_for_stack_a_with_shared_sha_and_state_success)` (bypassing controller-level signature check, simulating a legitimately signed request for `stack_a`).
5. Assert `commit_b.reload.deployable?` is now `true` — proving the equality `repository_owner_verified_by_signature == repository_owner(commit_b.stack)` does not hold, yet the write succeeded.
6. Stub/mock `Shipit::Command.expects(:start)` (or `Task#run`) and run the continuous-delivery job/`Stack#trigger_continuous_delivery` for `stack_b`; assert a `Deploy`/`Task` record is created and `Command.start` is invoked with `stack_b`'s deploy spec/env, without any action taken by `stack_b`'s own CI or maintainers.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-27)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?

        allow_concurrency = params.allow_concurrency.nil? ? params.force : params.allow_concurrency
        deploy = stack.trigger_deploy(commit, current_user, env: params.env, force: params.force,
                                                            allow_concurrency:)
        render_resource(deploy, status: :accepted)
```
