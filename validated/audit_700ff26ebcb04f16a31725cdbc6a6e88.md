### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a status webhook from repository A mutate CI state and trigger a deploy on any stack (repo B) sharing the same commit sha - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely by `sha`, with no scoping to the repository named in the verified webhook payload, unlike every other handler (`PushHandler`) which scopes through `Handler#stacks` (which resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))`). Because git commit SHAs are content-addressed and identical across forks/mirrors, an attacker who owns a repository A (with an existing, correctly-signed webhook integration) can post a `state: success` status event for a sha that also exists as an undeployed commit in an unrelated stack B, causing Shipit to record a success `Status` against stack B's commit and potentially trigger `ContinuousDeliveryJob` to deploy it.

### Finding Description
The binding that should hold is: `stack_that_receives_the_status.repository.full_name == payload['repository']['full_name']` (the repo named/authenticated in the webhook). This does **not** hold for the `status` event.

- `app/controllers/shipit/webhooks_controller.rb:24-30` (`verify_signature`) only proves the payload was signed for organization `repository_owner` (the org owning repo A) via `Shipit.github(organization: repository_owner).verify_webhook_signature`. It proves *who sent it*, not *which stack it may affect*. [1](#0-0) 

- `app/models/shipit/webhooks/handlers/handler.rb:32-38` defines the correct scoping primitive, `stacks`, which resolves the repository from `payload.dig('repository', 'full_name')` and restricts to that repository's own stacks. [2](#0-1) 

- `PushHandler#process` correctly uses this scoping: `stacks.not_archived.where(branch:).find_each { ... }`. [3](#0-2) 

- `StatusHandler#process` does **not** call `stacks` at all. It queries `Commit.where(sha: params.sha)` globally, across every stack/repository in the installation, and applies the attacker-supplied status to every match:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

- `Commit#create_status_from_github!` -> `add_status` -> `statuses.replicate_from_github!(stack_id, github_status)` persists a `Status` scoped to `commit.stack_id` (stack B's id, not the attacker's repo A), with `state: 'success'`. [5](#0-4) 

- `Status` model triggers `after_create :enable_ci_on_stack` and `after_commit :schedule_continuous_delivery`, both delegated to the commit's actual stack (stack B). [6](#0-5) 

- `Commit#deployable?` becomes `true` once the injected status makes the commit `success?` (assuming not locked/blocked): `!locked? && (stack.ignore_ci? || (success? && !blocked?))`. [7](#0-6) 

- `Stack#trigger_continuous_delivery` -> `next_commit_to_deploy` -> `deployable_commits` will then pick up commit C as deployable and call `trigger_deploy(commit, ...)`, creating and enqueuing a real `Deploy` on stack B. [8](#0-7) 

**Attack flow**: attacker owns/controls a repository A whose webhook is already validly configured with Shipit (satisfies `verify_signature`, per the stated attacker capability of "emit webhooks from a repository they own"). Because git SHAs are content-addressed, if repo A is a fork/mirror containing the same commit object as an undeployed commit C already tracked by unrelated stack B (with `continuous_deployment: true`), the attacker POSTs a `status` webhook to `/webhooks` with `repository.full_name = "attacker/repoA"`, `sha = C.sha`, `state = "success"`. `verify_signature` passes (it validates against repo A's owning org, which is legitimate). `StatusHandler#process` then matches **any** `Commit` row with that sha — including C, which belongs to stack B — and writes a success `Status` scoped to stack B, bypassing stack B's actual CI entirely. This is not blocked by `ExplicitParameters` (only validates the shape of `sha`/`state`, not repo ownership), nor by any model validation on `Commit`/`Status` (no cross-check between `payload['repository']` and `commit.stack.repository`).

### Impact Explanation
An attacker fully outside stack B's tenant can forge a CI success signal for stack B's existing commit and, if stack B has `continuous_deployment: true`, cause an unauthorized `Deploy` to be created and enqueued for stack B — a real deploy of code the attacker did not author and had no legitimate authority over, triggered purely via a webhook scoped to a repository the attacker controls. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." The blast radius spans every stack across every repository sharing the compromised commit sha (e.g., forks/mirrors of the same upstream, or any coincidental sha collision scenario the engine doesn't defend against), not just one target.

### Likelihood Explanation
Preconditions: the attacker needs (1) a repository whose webhook already validly signs requests to this Shipit instance (assumed granted per the audit's attacker capability), and (2) knowledge of a commit sha that exists, undeployed, in a victim stack B with `continuous_deployment: true`. Because git commit hashes are content-addressed, condition (2) is trivially satisfiable by forking/mirroring the target repository — any commit present in the upstream repo is automatically present with an identical sha in the fork. No secrets, sessions, or elevated GitHub roles are required beyond the baseline "attacker owns/controls repo A" assumption. This is cheap, repeatable against any stack with continuous deployment enabled, and requires no interaction from stack B's maintainers.

### Recommendation
Scope `StatusHandler#process` to the repository named in the verified webhook payload, mirroring `PushHandler`: only update commits belonging to stacks resolved via `stacks` (i.e., `Repository.from_github_repo_name(payload.dig('repository','full_name'))`), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, instead of an unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest (e.g. `test/models/shipit/webhooks/handlers/status_handler_test.rb` or as a controller test hitting `/webhooks`):
1. Create `repository_a` (owner: "attacker", name: "repoA") and `repository_b` (owner: "victim", name: "repoB").
2. Create `stack_a` under `repository_a`, and `stack_b` under `repository_b` with `continuous_deployment: true`.
3. Create `commit_c` under `stack_b` with `sha: "deadbeef..."`, no statuses (undeployed, pending state) — assert `commit_c.deployable?` is `false` before the webhook (binding LHS: stack receiving mutation = stack_b; binding RHS before: no mutation yet).
4. Stub `GithubHook#verify_signature`/`Shipit.github(organization: 'attacker').verify_webhook_signature` to return `true` (simulating a validly-configured webhook for repo A owned by attacker), matching the existing pattern in `test/controllers/webhooks_controller_test.rb`.
5. POST to `/webhooks` with header `X-Github-Event: status` and body `{ "sha" => commit_c.sha, "state" => "success", "repository" => { "full_name" => "attacker/repoA", "owner" => { "login" => "attacker" } } }`.
6. Assert `commit_c.reload.deployable?` is now `true` (proving cross-repo mutation: stack whose CI state changed = stack_b, but payload's `repository.full_name` = "attacker/repoA" ≠ stack_b's repository "victim/repoB" — binding broken).
7. Wrap step 5 in `assert_enqueued_with(job: ContinuousDeliveryJob)` and, after `perform_enqueued_jobs`, assert `Deploy.count` for `stack_b` increased by 1, confirming an unauthorized deploy of `commit_c` was triggered purely by a webhook scoped to repo A.

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

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

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
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/models/shipit/stack.rb (L210-243)
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

    def schedule_merges
      ProcessMergeRequestsJob.perform_later(self)
    end

    def next_commit_to_deploy
      commits_to_deploy = commits.order(id: :asc).newer_than(last_deployed_commit).reachable.preload(:statuses)
      if maximum_commits_per_deploy
        commits_with_max_applied = commits_to_deploy.limit(maximum_commits_per_deploy)
        deployable_commits(commits_with_max_applied) || deployable_commits(commits_to_deploy)
      else
        deployable_commits(commits_to_deploy)
      end
    end
```
