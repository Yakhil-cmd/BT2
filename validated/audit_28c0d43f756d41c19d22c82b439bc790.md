### Title
StatusHandler updates commit statuses and triggers deploys for **any** stack sharing a commit sha, ignoring the webhook's own repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely by `Commit.where(sha: params.sha)`, without scoping to the repository identified in the webhook payload. Any repository whose GitHub-signed `status` event names a sha that also exists as a `Commit` row in an unrelated stack will create a `Status` there too, which can trigger `ContinuousDeliveryJob` and an unauthorized deploy on that unrelated stack.

### Finding Description
The broken binding is: `params.dig('repository', 'full_name')` (the webhook's authenticated repository) should equal `commit.stack.repository.full_name` for every `Commit` that receives a new `Status` from this webhook. This equality is never enforced.

`WebhooksController#verify_signature` only proves the request came from GitHub for the organization named in the payload (`Shipit.github(organization: repository_owner)`), i.e., it authenticates *who sent the request*, not *which commits the payload is allowed to touch*. [1](#0-0) 

Other handlers scope their effect to the payload's own repository via `Handler#stacks`, which resolves `Repository.from_github_repo_name(repository_name)` before touching any records: [2](#0-1) 

`StatusHandler#process`, however, bypasses this scoping mechanism entirely and queries the global `Commit` table by `sha` alone: [3](#0-2) 

If a git commit object with sha `S` (identical tree, parents, author/committer, message/timestamps — e.g. a shared upstream open-source commit merged into two unrelated products) is present as a `Commit` row in both Stack V1 (repo A) and Stack V2 (repo B), a single genuine, correctly-signed GitHub `status` webhook for repo A/sha `S` will match `Commit.where(sha: S)` in **both** stacks, and call `commit.create_status_from_github!(params)` on both. Creating that `Status` triggers `Commit#schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob.perform_later(stack)` for whichever stack owns each matched commit: [4](#0-3) 

`ContinuousDeliveryJob#perform` then unconditionally deploys if the stack is continuous-deployment enabled and not occupied: [5](#0-4) [6](#0-5) 

The existing test suite already demonstrates that creating a `Status` with state `success` on a commit is sufficient to enqueue and run `ContinuousDeliveryJob` and increase `Deploy.count`: [7](#0-6) 

None of the listed guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema in `StatusHandler.params`) check that the matched `Commit#stack`'s repository equals the payload's repository — they validate payload shape and sender authenticity only, not per-commit tenant ownership.

### Impact Explanation
An attacker who controls (or merely triggers CI/status reporting on) their own onboarded repository can, by naming a sha that coincidentally (or via crafted shared history) also exists in a victim stack's commit table, cause an unrelated victim stack to receive a `Status` record it never legitimately produced, and — if that victim stack has continuous deployment enabled — trigger an unauthorized deploy via `ContinuousDeliveryJob`. This is a cross-tenant write (`Status` created against a foreign stack's `Commit`) and an unauthorized deploy, matching the Critical category "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy." It is repeatable against any number of stacks that happen to share a commit sha with the attacker's own repository, each additional forged/real status event compounding the effect.

### Likelihood Explanation
Exploitation requires: (1) the attacker owns/controls a repository already onboarded as a Shipit stack (so a genuine GitHub `status` webhook for that repo is correctly signed and passes `verify_signature`), and (2) a sha collision — i.e., an identical commit object present as a `Commit` row in a victim stack, which is realistic when two repositories share history (forks, vendored/subtree-merged upstream commits, monorepo splits). The attacker does not need any Shipit secret, session, or API token — only the ability to produce/report a status on a commit of their own choosing in their own repository. This is plausible but conditioned on a real sha collision existing between the attacker's repo and a target stack.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the payload's own repository (mirroring `Handler#stacks`), e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` or join through `Stack -> Repository` matching `repository_name` before calling `create_status_from_github!`, rather than querying `Commit` globally by `sha`.

### Proof of Concept
1. Fixtures: create `Stack` V1 with `Repository` `owner1/repoA`, `Stack` V2 with `Repository` `owner2/repoB`. Enable `continuous_deployment: true` on both.
2. Create `Commit` `c1` on V1 and `Commit` `c2` on V2 both with `sha: "deadbeefcafef00d"`.
3. Stub `GithubHook#verify_signature` (or `Shipit.github(...).verify_webhook_signature`) to return `true` to simulate a genuinely GitHub-signed `status` event for `owner1/repoA`.
4. `POST /webhooks` with `X-Github-Event: status`, body `{"sha"=>"deadbeefcafef00d", "state"=>"success", "repository"=>{"full_name"=>"owner1/repoA", "owner"=>{"login"=>"owner1"}}}`.
5. Assert:
   - `V1.reload.deploys.count` increased (expected, legitimate).
   - `V2.reload.deploys.count` also increased — proving the single webhook for repo A crossed into V2/repo B's tenant boundary, which should be `assert_no_difference`/false but is observed `true`. [3](#0-2) [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```

**File:** app/models/shipit/stack.rb (L210-228)
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
```

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
    end
```
