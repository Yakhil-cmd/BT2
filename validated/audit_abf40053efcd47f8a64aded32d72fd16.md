### Title
Cross-repository SHA collision in `StatusHandler` triggers unauthorized continuous delivery deploy - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` matches incoming GitHub `status` webhooks against `Commit` records purely by `sha`, with no scoping to the repository that authenticated the webhook. Because `verify_signature` only proves the payload came from *some* registered GitHub organization/repo, not that the `sha` belongs to that repository, an attacker who controls any repository onboarded to Shipit (including their own) can produce a commit with identical content/SHA to Stack A's HEAD and post a passing status for it, which Shipit applies to Stack A's commit and can cascade into `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery`, starting a real deploy of Stack A using Stack A's own credentials.

### Finding Description
The broken binding: `params.dig('repository','full_name') (webhook signer's repo)` should equal `commit.stack.repository.full_name (repo owning the sha being updated)`; instead `StatusHandler` never checks this.

- `WebhooksController#verify_signature` validates the HMAC signature using `Shipit.github(organization: repository_owner)`, i.e., it confirms the payload was signed by *a* registered organization/repo's webhook secret [1](#0-0) . It never checks that the `sha` in the payload actually belongs to `repository_owner`'s repo.
- `StatusHandler#process` looks up commits solely by `sha`, globally, across the whole `commits` table, and applies the status to whatever it finds: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) . Note the base `Handler` class does provide a repository-scoped `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) [3](#0-2) , but `StatusHandler` does not use it — it bypasses that scoping entirely.
- Creating a `Status` triggers `after_commit :schedule_continuous_delivery` on the `Status` model, which calls `commit.schedule_continuous_delivery` [4](#0-3) .
- `Commit#schedule_continuous_delivery` checks `deployable? && stack.continuous_deployment? && stack.deployable?` and, if true, enqueues `ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)` [5](#0-4) . This job eventually calls `Stack#trigger_continuous_delivery`, which starts a real `Deploy` using Stack A's own `GITHUB_TOKEN`/deploy spec.

Attack flow: the attacker creates a git commit with byte-identical tree/content to Stack A's HEAD commit inside a repository they control (this is possible whenever the content is known/public, since SHA-1 commit IDs are a pure function of content — no secret is required to reproduce them), causing the SHA to collide. They push that commit to their own repo (registered with Shipit under their own webhook secret) and cause a `success` status to be posted for that SHA (e.g., via their own CI, or by directly emitting a `status` event since GitHub will sign it with the attacker's own repo's legitimate webhook secret). `verify_signature` passes because the signature matches the attacker's own repo's secret. `StatusHandler` then finds Stack A's identical-SHA `Commit` row (unscoped by repo) and creates a `Status` against it, satisfying `deployable?` and cascading into a real deploy of Stack A.

Existing guards do not prevent this: `verify_signature` authenticates the sender's own repository, not the target of the mutation; `drop_unhandled_event`/`ExplicitParameters` validate payload shape, not repo/sha binding; there is no `Repository`- or `Stack`-scoped filter in `StatusHandler#process` unlike other handlers that use the `stacks` helper.

### Impact Explanation
An attacker with control of an arbitrary GitHub repository (which merely needs to be independently registered/onboarded with Shipit — no privilege on Stack A) can inject a `Status` record onto Stack A's commit and trigger `Stack#trigger_continuous_delivery`, causing an unauthorized `Deploy` to run with Stack A's `GITHUB_TOKEN` and deploy spec. This is a payload from one repository mutating another repository's commit/stack state and causing an unauthorized deploy — matching the Critical impact category (unauthorized deploy executed with another party's credentials, with no access to that party's repo).

### Likelihood Explanation
Preconditions: Stack A must have `continuous_deployment?` true and be `deployable?` (no active/locked deploy), and its HEAD commit must become `deployable?` from the forged status. The attacker needs their own onboarded repository within the same Shipit instance (a low bar for any internet user who can get a repo registered, or who already owns one), and needs a commit whose content matches Stack A's HEAD SHA — feasible for public repositories/commits since git SHAs are content-derived and computable without secrets. No Shipit or GitHub secret material is required, satisfying the "unprivileged attacker" constraint. The attack is repeatable against any stack/repository whose commit SHAs the attacker can reproduce.

### Recommendation
Scope `StatusHandler#process` to the repository that signed the webhook, mirroring the base `Handler#stacks` helper: resolve the target `Stack`s via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, and only update/create statuses for commits belonging to those stacks, instead of matching `Commit` by `sha` globally.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, out-of-scope directory noted but describing the intended assertions):
1. Create `stack_a` with `repository` `org-a/repo-a`, `continuous_deployment: true`, and a `commit` with `sha: "deadbeef..."` that is `deployable?` and is `stack_a.deployable?`.
2. Create an unrelated `stack_b`/`repository` `attacker/repo-b` with no relation to `stack_a`.
3. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` where `payload['repository']['full_name'] == 'attacker/repo-b'` but `payload['sha'] == stack_a.commits.last.sha` and `state == 'success'`.
4. Assert both sides of the equality: `payload.dig('repository','full_name')` (`attacker/repo-b`) does NOT equal `stack_a.repository.full_name` (`org-a/repo-a`), yet a `Status` is created on `stack_a`'s commit — proving the mismatch is not enforced.
5. Using `ActiveJob::TestHelper`, assert `ContinuousDeliveryJob` was enqueued with `stack_a` as argument, then perform the job and assert `Deploy.create!` (or equivalent) is invoked with `stack_id: stack_a.id`, with no participation from `org-a`.

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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
