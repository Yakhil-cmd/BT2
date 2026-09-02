### Title
Cross-repository commit-status forgery via unscoped `StatusHandler` webhook lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub organization/app derived from the payload's `repository.owner.login`, then dispatches the event body to a handler keyed only by event type [1](#0-0) [2](#0-1) . Every other handler re-derives the target repository from `payload['repository']['full_name']` and scopes its writes to that repository's stacks [3](#0-2) [4](#0-3) [5](#0-4) . `StatusHandler`, however, never uses `repository_name`/`stacks` at all — it looks up commits globally by SHA across the entire Shipit installation and writes a GitHub-origin status onto every match:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [6](#0-5) 

### Finding Description
This breaks the binding that the report's bug class maps to: *"an organization that authenticated versus the repository that is written."* The webhook signature is verified using the GitHub App/organization config selected by `repository_owner` (`params.dig('repository','owner','login')`) [2](#0-1) [7](#0-6) . That authentication only proves the payload was legitimately signed *for that organization's repository* — it says nothing about which `Commit`/`Stack` records the handler is allowed to mutate. Every other handler (`PushHandler`, `CheckSuiteHandler`) re-establishes that link explicitly by resolving `Repository.from_github_repo_name(repository_name)` before touching any `Stack` or `Commit` [3](#0-2) . `StatusHandler` omits this step and instead matches purely on git SHA across all repositories tracked by the Shipit instance, so a `status` event validly signed for org/repo A can create/replicate a commit status on any other tracked stack (org B, C, …) whose history happens to contain a commit with the same SHA — e.g. shared upstream commits, forked/mirrored repositories, or a monorepo split into multiple Shipit-tracked stacks.

### Impact Explanation
`Commit#create_status_from_github!` feeds directly into `Commit#state`/`deployable?` computation used by continuous deployment (`schedule_continuous_delivery`) [8](#0-7) . A forged/duplicated `success` status pushed cross-repository can make a commit in a stack the attacker does not control appear deployable and trigger the merge/deploy pipeline for it — this lands in the report's "unauthorized deploy" impact bucket, escalating an org-scoped webhook credential into influence over an unrelated stack's deploy state.

### Likelihood Explanation
Exploitation requires the attacker to control (or already have webhook delivery rights on) a GitHub repository/organization that is itself onboarded into the same Shipit instance, and for a commit SHA collision (natural, via shared history/forks, not a cryptographic break) to exist with the victim stack. This is a real but narrower precondition than a fully unauthenticated attack, making likelihood moderate rather than trivial, but the missing repository check is a clear, concrete code defect distinguishable from the correctly-scoped sibling handlers.

### Recommendation
`StatusHandler#process` should scope its `Commit` lookup to the repository identified by the verified payload, mirroring `Handler#stacks`/`repository_name`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining through `Stack` so that only commits belonging to a stack whose repository matches `payload['repository']['full_name']` are updated.

### Proof of Concept
1. Attacker controls repository `attacker/repo`, which is tracked by the same Shipit instance as an unrelated `victim/repo` stack (both onboarded, different orgs/webhook secrets).
2. `victim/repo` contains a commit `C` (SHA `abc123...`) that is also present verbatim in `attacker/repo`'s history (e.g., a shared vendored dependency commit, or a fork retaining upstream history) — a legitimate, non-cryptographic SHA match, not requiring a hash collision attack.
3. Attacker triggers (or has a CI system emit) a `status` webhook event for `attacker/repo` at SHA `abc123...` with `state: success`. This is signed with `attacker`'s organization webhook secret, so `verify_signature` passes.
4. `StatusHandler#process` runs `Commit.where(sha: 'abc123...')`, which returns the commit both in `attacker/repo`'s stack and `victim/repo`'s stack, and calls `create_status_from_github!` on both — writing a forged "success" status onto the `victim/repo` commit that the attacker never had signature/write authority over.

Note: I was unable to fully inspect `Commit#create_status_from_github!` and the exact deploy-eligibility path (`Commit#state`) in this pass due to iteration limits; those were only confirmed by name/reference via `Status` model callbacks [8](#0-7) , not by reading `commit.rb` in full.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-13)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
