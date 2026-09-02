### Title
`StatusHandler#process` writes statuses by bare `sha` with no repository scoping, letting a status for one repository flip deployability/CI-gate on another stack that shares the commit - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha).each` and applies the incoming GitHub status to every matching `Commit` record, regardless of which repository the webhook payload says it came from. Unlike other handlers in this engine, it never uses the base `Handler#stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) to constrain the update to the stack(s) belonging to the authenticated repository, so a `status` event tied to one repository can flip CI/deployability state on a `Commit` belonging to a different `Stack` whenever the same `sha` exists in both.

### Finding Description
The broken binding is: `commit.stack.github_repo_name` (or `commit.stack_id`) should equal `payload.dig('repository', 'full_name')` before a status is applied to that commit. This is enforced elsewhere in the engine — the base class exposes exactly this scoping primitive: [1](#0-0) 

But `StatusHandler#process` never calls it: [2](#0-1) 

It queries `Commit` globally by `sha` and, for every match, calls `commit.create_status_from_github!(params)`, which creates a `Status` scoped to that commit's own `stack_id`: [3](#0-2) 

Creating a `Status` record fires `after_create :enable_ci_on_stack` and `after_commit :schedule_continuous_delivery`: [4](#0-3) 

`schedule_continuous_delivery` on `Status` delegates to `commit.schedule_continuous_delivery`, and `Commit` fires the same hook on create, which is how a `success` state for the configured CI context (e.g. `continuous-integration/travis-ci`) can trigger `ContinuousDeliveryJob` and an automatic deploy when `stack.continuous_deployment` is enabled — this deploy runs under the stack's configured bot identity (`Shipit.user`, from `bot_login`), not an authenticated human/GitHub identity. The same mechanism, applied with `state: failure/error`, can block deploys/merges that would otherwise be allowed (`ProcessMergeRequestsJob`/deployability checks read `commit.state`, computed from `statuses`).

`verify_signature` in `Shipit::WebhooksController` only validates the HMAC signature against the GitHub App configured for the payload's `repository.owner.login` (or `organization.login`) — it authenticates *that the sender knows the org's webhook secret*, not that the *sha* or *stack* the handler subsequently mutates belongs to that same repository: [5](#0-4) 

So a validly-signed `status` webhook for Repository A (which the sender legitimately controls/authenticates, e.g. their own CI posting a real status for their own PR/branch) is dispatched to `StatusHandler`, which then updates **every** `Commit` row across the database sharing that `sha` — including `Commit` rows belonging to unrelated `Stack`s (most realistically, multiple Shipit stacks tracking the *same underlying GitHub repository*, e.g. staging/production environments, or repos with shared git history/mirrors). None of `verify_signature`, `drop_unhandled_event`, or the `ExplicitParameters` schema in `StatusHandler` (`sha`, `state`, `context`, etc.) validate that the target commit's stack corresponds to the authenticated repository, so the divergence between "authenticated repository" and "repository actually mutated" is never checked.

### Impact Explanation
A status event authenticated for one repository can create a `Status` on a `Commit` belonging to a different `Stack` that happens to reference the same `sha` (a common real-world case: multiple stacks tracking the same repository across environments). Because status creation triggers `enable_ci_on_stack` and `schedule_continuous_delivery`, this can:
- Force an unwanted automatic deploy on a victim stack with `continuous_deployment` enabled, executed under the stack's `Shipit.user`/bot identity rather than any legitimately authorized actor — an unauthorized deploy.
- Or flip a required CI context to `failure`/`error`, blocking a legitimate deploy/merge on the victim stack.

This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." Repeatable per matching `sha`/stack pair, and not limited to a single tenant if shas collide across multiple onboarded repositories/stacks.

### Likelihood Explanation
The precondition is that the same commit `sha` must exist as a `Commit` row in more than one `Stack` (common when a repository is tracked by multiple Shipit stacks, e.g. staging and production, or a fork/mirror sharing history) and that the victim stack has `continuous_deployment` enabled with a `bot_login` configured. The attacker must be able to get a validly signed `status` webhook delivered for *some* repository they legitimately control (their own CI posting to their own PR/branch is normal, not privileged) — signature verification is org-scoped, not commit/stack-scoped, so it does not prevent the cross-stack write once the webhook is accepted. No Shipit session, API token, or webhook secret for the victim's organization is needed if the attacker's own repository/org is already onboarded to the same Shipit instance.

### Recommendation
In `StatusHandler#process`, scope the lookup to commits belonging to stacks for the authenticated repository, mirroring the base `Handler#stacks` helper, e.g. only update `Commit` records where `commit.stack.github_repo_name == repository_name` (derived from `payload.dig('repository', 'full_name')`) instead of matching by bare `sha` across the whole `Commit` table.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, hypothetical):
```ruby
test "status for repository A does not affect a commit with the same sha on stack B" do
  stack_a = shipit_stacks(:shipit)                 # tracks repo "shopify/shipit-engine"
  stack_b = shipit_stacks(:cyclimse)                # different stack, continuous_deployment: true, bot_login configured
  shared_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

  commit_a = stack_a.commits.create!(sha: shared_sha, message: "m", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)
  commit_b = stack_b.commits.create!(sha: shared_sha, message: "m", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "context" => "continuous-integration/travis-ci",
    "repository" => { "full_name" => stack_a.github_repo_name, "owner" => { "login" => stack_a.repository.owner } }
  }

  assert_no_difference -> { commit_b.statuses.count } do
    assert_difference -> { commit_a.statuses.count }, 1 do
      Shipit::Webhooks::Handlers::StatusHandler.call(payload)
    end
  end

  refute_enqueued_with(job: ContinuousDeliveryJob, args: [stack_b])
end
```
Binding checked: before processing, `commit_a.stack_id == stack_a.id` and `commit_b.stack_id == stack_b.id`, with `stack_a.github_repo_name != stack_b.github_repo_name`. After processing the status authenticated for `stack_a.github_repo_name`, the assertion shows `commit_b.statuses.count` unexpectedly changes and `ContinuousDeliveryJob` is enqueued for `stack_b`, proving the invariant "a status affects only the repository that authenticated it" is violated by current `StatusHandler#process` code (`Commit.where(sha: params.sha).each`).

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

**File:** app/models/shipit/status.rb (L18-21)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```
