### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` triggers unauthorized continuous deployment - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits to attach a forged GitHub status to using `Commit.where(sha: params.sha)` with no scoping by the webhook's own `repository.full_name`, unlike every sibling handler (`PushHandler`, `CheckSuiteHandler`) which route through the `Handler#stacks` helper that filters by `repository_name`. Any commit sha value the attacker names in their own repository's status webhook, if it string-matches a sha already tracked by an unrelated victim stack, results in a `Status` record being created against the victim's commit, which can cascade into `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery` and an unauthorized deploy.

### Finding Description
The broken binding is: `payload.dig('repository','full_name')` (the repo the webhook signature was verified for) **must equal** the `stack.repository.full_name` of the `Commit` whose `Status` is created, but `StatusHandler#process` never enforces this.

Compare the two handlers:
- `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) uses `stacks.not_archived.where(branch:)`, where `stacks` is `Repository.from_github_repo_name(repository_name)&.stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), i.e., scoped strictly to the repository named in the current payload. [1](#0-0) 
- `StatusHandler#process` instead does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 
This is a **global, unscoped query across every stack/repository** in the Shipit instance, keyed only on the literal `sha` string supplied by the attacker's own webhook payload. It never consults `repository_name`/`stacks`.

`verify_signature` in `WebhooksController` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only proves that the payload was signed for `repository_owner = params.dig('repository','owner','login')` — i.e., that the webhook genuinely originates from a repo/org the app is installed on. It does **not** verify that the `sha` inside that payload belongs to a commit of that same repository. Because a GitHub App's webhook secret is shared across all installations of the app, an attacker who can get the Shipit GitHub App installed on (or simply push webhooks that are routed for) their own repository can produce a validly-signed `status` event whose `repository.full_name` is `attacker/evil` but whose `sha` field is copied verbatim from a publicly-known commit sha of the victim's tracked stack (commit shas are not secrets — they are visible in the victim's public GitHub history/PRs or in Shipit's own UI).

Exploit flow:
1. Attacker identifies a sha already tracked in a victim stack with `continuous_deployment: true`, e.g., `ba5eba11...` (from GitHub or the Shipit UI).
2. Attacker sends `POST /webhooks` with `X-Github-Event: status`, a body `{ sha: 'ba5eba11...', state: 'success', branches: [...], repository: { full_name: 'attacker/evil', owner: { login: 'attacker' } } }`, signed with the (legitimately obtained, e.g. app-installed-on-own-account) webhook secret for `attacker`'s org.
3. `verify_signature` passes because the signature is valid for `attacker`'s org.
4. `StatusHandler#process` runs `Commit.where(sha: 'ba5eba11...')`, finds the victim's commit (owned by an entirely different `Repository`/`Stack`), and calls `commit.create_status_from_github!(params)`.
5. `Commit#create_status_from_github!` → `add_status` → `statuses.replicate_from_github!` creates a `Status` record with `state: 'success'` on the victim commit.
6. `Status`'s `after_commit :schedule_continuous_delivery` (`app/models/shipit/status.rb:19,42-44`) calls `commit.schedule_continuous_delivery`, which (if `deployable?`, `stack.continuous_deployment?`, `stack.deployable?`) enqueues `ContinuousDeliveryJob` (`app/models/shipit/commit.rb:281-287`). [3](#0-2) 
7. `ContinuousDeliveryJob#perform` (`app/jobs/shipit/continuous_delivery_job.rb:10-21`) calls `stack.trigger_continuous_delivery`, which (given the stated preconditions: not locked, not `active_task?`, `deployment_checks_passed?`, `cached_deploy_spec` present) proceeds to `build_deploy`/`trigger_deploy` → `Task#enqueue` → `Command#start`/`PTY.spawn`, running the victim stack's real deploy script. [4](#0-3) 

Existing guards do not catch this: `drop_unhandled_event`/`check_if_ping` are event-type gates unrelated to repo scoping; `ExplicitParameters` (`params do requires :sha ... end`) only validates field types/presence, not repository ownership; `verify_signature` authenticates the sending org, not the sha-to-repo relationship; and there is no `Repository`/`Stack` lookup anywhere in `StatusHandler#process` to bind the two together, unlike `PushHandler`/`CheckSuiteHandler`.

### Impact Explanation
This is a **payload for one repository mutating another repository's commit/task state and triggering an unauthorized deploy**, which the rubric places at Critical severity: an attacker with no privileges on the victim's Shipit instance or repository can force execution of the victim's real deploy pipeline (`Command`/`PTY.spawn` on the deploy host) simply by knowing a tracked commit sha and controlling any repository the Shipit GitHub App/webhook is willing to accept signed events for. It is repeatable against any stack with `continuous_deployment: true` and any known sha, and the blast radius spans all tenants/stacks sharing the same Shipit instance, since the vulnerable query is global (`Commit.where(sha:)`, unscoped to any single organization/repository).

### Likelihood Explanation
Preconditions required: the victim stack must have `continuous_deployment: true`, a `cached_deploy_spec`, not be locked, not have an active task, and `deployment_checks_passed?` — all realistic default configurations for CD-enabled stacks. The attacker needs: (a) a way to send a validly-signed `status` webhook for some repository the app trusts (e.g., their own GitHub account/org if the Shipit GitHub App is installable by arbitrary accounts, which is standard for GitHub Apps whose webhook secret is shared across installations), and (b) knowledge of an already-tracked victim commit sha, which is generally public. No Shipit session, API token, or secret is required. This is low-cost and repeatable per targeted sha/stack.

### Recommendation
Scope `StatusHandler#process` to the repository named in the verified payload, mirroring `PushHandler`/`CheckSuiteHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This binds the `Commit` lookup to `Repository.from_github_repo_name(repository_name)`, ensuring a status webhook can only mutate commits belonging to the repository it was actually sent for.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (illustrative)
test ":status from an unrelated repository forges a status on a victim commit and triggers an unauthorized deploy" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(continuous_deployment: true)
  victim_commit = victim_stack.commits.last # sha known/public

  request.headers['X-Github-Event'] = 'status'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # attacker obtained a valid signature for their own org

  attacker_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'branches' => [{ 'name' => victim_stack.branch }],
    'repository' => { 'full_name' => 'attacker/evil', 'owner' => { 'login' => 'attacker' } }
  }.to_json

  assert_difference -> { Shipit::Status.where(commit: victim_commit).count }, 1 do
    post :create, body: attacker_payload, as: :json
  end

  assert_difference -> { Shipit::Deploy.where(stack: victim_stack).count }, 1 do
    perform_enqueued_jobs only: Shipit::ContinuousDeliveryJob
  end
end
```
Both sides of the binding should be asserted: `victim_commit.stack.repository.full_name` ('the-org/shipit') vs `'attacker/evil'` (from the payload used for signature verification) — they differ, yet the `Status`/`Deploy` are created against `victim_stack`, proving the vulnerability. After applying the recommended fix (scoping via `stacks`), the same test should show `assert_no_difference` for both `Status` and `Deploy` counts.

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
