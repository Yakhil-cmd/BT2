### Title
`ReopenedHandler#unarchive?` operator-precedence bug ignores `review_stacks_enabled` for `allow_with_label`/`prevent_with_label` repos, re-triggering provisioning of attacker-controlled PR - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler#unarchive?` has the identical missing-parentheses bug already present in `OpenedHandler#provision?`: `review_stacks_enabled` is only `&&`-anded to the `allow_all?` branch, not to the whole expression, because `&&` binds tighter than `||` in Ruby. As a result, on a repository configured with `provisioning_behavior: allow_with_label` or `prevent_with_label`, a `pull_request.reopened` webhook still calls `ReviewStackAdapter#unarchive!` (which calls `Shipit::ReviewStackProvisioningQueue.add`) even when `review_stacks_enabled` is `false`.

### Finding Description
The claimed binding is: `review_stacks_enabled == false` ⇒ no provisioning queue entry is created for any pull-request webhook event, i.e. `unarchive? == false` for all `provisioning_behavior` values when `review_stacks_enabled` is `false`.

The actual code in `app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb:70-75`: [1](#0-0) 
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Ruby's `&&`/`||` precedence makes this parse as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && label_present) || (prevent_with_label? && !label_present)`

`review_stacks_enabled` only gates the `allow_all?` term; the `allow_with_label?` and `prevent_with_label?` terms are entirely independent of `review_stacks_enabled`. Since `review_stacks_enabled` is a repository attribute independent from `provisioning_behavior` (confirmed by `configure_provisioning_behavior` test helpers that set both independently, e.g. `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb:200-207`), an operator can have `review_stacks_enabled: false` with `provisioning_behavior: prevent_with_label` (or `allow_with_label`).

`process` calls `stack.unarchive!` unconditionally when `respond_to_pull_request_reopened?` (i.e. `unarchive?`) is true: [2](#0-1) 

`ReviewStackAdapter#unarchive!` then creates or re-enqueues the stack: [3](#0-2) 
and for a missing stack calls `create!`, which sets `branch: params.pull_request.head.ref` from the attacker-controlled payload and calls `Shipit::ReviewStackProvisioningQueue.add(stack)`: [4](#0-3) 

**Attacker's exact request**: open a PR from their own fork/branch on a repository where the operator set `review_stacks_enabled: false` but left `provisioning_behavior` at `prevent_with_label` (or `allow_with_label`, matching label state); the repository's PR-created stack gets closed (archived) at some point, then the attacker triggers `pull_request.closed` followed by `pull_request.reopened` webhooks (both are unauthenticated app-level webhook deliveries subject only to signature verification, which the attacker does not need to forge because they are simply performing normal GitHub actions—closing/reopening their own PR—that GitHub itself sends signed webhooks for). This re-creates/re-queues the review stack and re-provisions it, re-running `shipit.yml`/deploy steps sourced from the attacker's branch.

**Why existing guards don't catch this**: `verify_signature`/`GitHubApp#verify_webhook_signature` only validate that GitHub sent the webhook — they do not validate the *content* of the `review_stacks_enabled` decision, and the bug is a logic error in a downstream handler, not a signature issue. `ExplicitParameters` schema only validates payload shape. There is no model validation on `Repository#review_stacks_enabled` vs `provisioning_behavior` combination preventing this state. The engine's own test suite (`test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`) never asserts `review_stacks_enabled: false` combined with `allow_with_label`/`prevent_with_label`, so this divergence is untested and unnoticed. This is the exact same underlying bug the question already established exists in `OpenedHandler#provision?` — `ReopenedHandler#unarchive?` contains the identical unparenthesized expression, so it inherits the same defect.

### Impact Explanation
When triggered, `Shipit::ReviewStackProvisioningQueue.add(stack)` schedules provisioning of a review stack whose `branch` is taken directly from the attacker's pull request head ref. Provisioning executes the repository's deploy/provisioning pipeline (`shipit.yml`) checked out from that branch, i.e. attacker-controlled deploy steps run on the deploy host — this is a Critical-class "unauthorized deploy" / RCE-via-CI-pipeline impact, scoped to the repository the attacker has PR access to (their own fork/branch within a repo they can open PRs against). It does not cross repository/tenant boundaries beyond the one repository whose maintainers explicitly intended to have review-stack auto-provisioning turned off (`review_stacks_enabled: false`) — but for that repository, the security control is silently bypassed and is repeatable for every close/reopen cycle.

### Likelihood Explanation
Preconditions: repository has `review_stacks_enabled: false` (operator intent: disable review-stack auto-provisioning) but `provisioning_behavior` is `allow_with_label` or `prevent_with_label` (rather than `allow_all`) — a configuration state the UI/model does not prevent. The attacker only needs the ability to open/close/reopen a pull request against that repository (fork-based contributors typically can), and to control label state to match the required branch (`allow_with_label` + has label, or `prevent_with_label` + no label — the latter is the default no-label state, requiring zero extra attacker action). No secrets, tokens, or elevated permissions are needed. This is low-cost and fully repeatable.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the entire disjunction, matching the same fix needed in `OpenedHandler#provision?`:
```ruby
def unarchive?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the identical fix to `OpenedHandler#provision?` since it shares the exact same defect.

### Proof of Concept
minitest under `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`:
```ruby
test "does not unarchive/provision stacks when review_stacks_enabled is false, even for prevent_with_label with no label" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # binding: review_stacks_enabled == false
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] = []  # no label -> prevent_with_label branch matches

  assert_equal false, repository.reload.review_stacks_enabled  # left side of binding
  Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process

  assert stack.reload.archived?, "Stack must remain archived when review_stacks_enabled is false"
  assert_not stack.awaiting_provision?, "No provisioning queue entry should exist when review_stacks_enabled is false"
end
```
Given the current code, this assertion fails: `unarchive?` evaluates true via the `prevent_with_label? && !label_present` clause regardless of `review_stacks_enabled`, `stack.unarchive!` runs, `Shipit::ReviewStackProvisioningQueue.add(stack)` is called, and the stack is unarchived and queued for provisioning — demonstrating the broken binding.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-50)
```ruby
          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-85)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end
```
