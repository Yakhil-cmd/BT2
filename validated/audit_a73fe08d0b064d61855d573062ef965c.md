Confirmed: `create!` calls `Shipit::ReviewStackProvisioningQueue.add(stack)` unconditionally, so any stack created via the broken `provision?` branch is actually enqueued for provisioning, executing real work against operator intent.

### Title
`OpenedHandler#provision?` operator-precedence bug bypasses `review_stacks_enabled=false` for `prevent_with_label` repositories - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`PullRequest::OpenedHandler#provision?` combines `review_stacks_enabled` with the `provisioning_behavior` checks using Ruby's operator precedence where `&&` binds tighter than `||`, so `review_stacks_enabled` is only ANDed with the `allow_all?` clause and not with the `allow_with_label?`/`prevent_with_label?` clauses. As a result, a repository configured with `review_stacks_enabled = false` and `provisioning_behavior = prevent_with_label` will still auto-provision a `ReviewStack` for any opened pull request that omits the provisioning label, contradicting the operator's explicit intent to disable review stacks.

### Finding Description
The intended binding is: for any created `ReviewStack`, `repository.review_stacks_enabled == true` must hold. The actual code is: [1](#0-0) 

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Due to Ruby precedence, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)`. The third disjunct, `(prevent_with_label? && !has_label)`, never references `review_stacks_enabled`, so it evaluates to `true` even when `review_stacks_enabled` is `false`, as long as `provisioning_behavior == "prevent_with_label"` and the PR carries no provisioning label.

Exploit flow: an unprivileged GitHub user opens a pull request (with `labels: []`, no provisioning label) against a repository whose operator has set `review_stacks_enabled = false` and `provisioning_behavior = prevent_with_label`. GitHub emits a `pull_request` `opened` webhook, which reaches `OpenedHandler#process` via the normal webhook dispatch path (webhook signature verification and payload schema validation pass normally, since this is a legitimate, correctly-signed GitHub delivery for a repo already tracked by Shipit — no forged signature is required). `respond_to_pull_request_opened?` calls `provision?`, which returns `true` via the third disjunct, and `ReviewStackAdapter#find_or_create!` creates a `Shipit::ReviewStack`, builds its `PullRequest`, and immediately calls `Shipit::ReviewStackProvisioningQueue.add(stack)`: [2](#0-1) 

None of `verify_signature`/`drop_unhandled_event`/`ExplicitParameters` schema checks guard against this — they validate the webhook's authenticity and payload shape, not the business-level provisioning gate, so they do not catch the logic bug. The existing test suite has no test combining `review_stacks_enabled: false` with `behavior: :prevent_with_label`, so this branch is uncovered.

### Impact Explanation
Any user able to open a pull request against a repository tracked by Shipit and configured with `review_stacks_enabled=false` + `provisioning_behavior=prevent_with_label` can force Shipit to create a `ReviewStack` record and enqueue it for provisioning, causing the associated deployment/provisioning `Task` to run — against the operator's explicit configuration to disable review stacks for that repo. This is repeatable per PR (one stack per PR number) and confined to repositories using this specific configuration, but for those repositories it is a full bypass of the disable switch, causing unauthorized task execution.

### Likelihood Explanation
Requires the target repository to be tracked by Shipit with `review_stacks_enabled=false` and `provisioning_behavior=prevent_with_label` (an operator-chosen, plausible configuration meant to fully disable auto-provisioning while still supporting the label mechanic for other event types). Attacker cost is trivial: open a PR without the provisioning label. No secrets, elevated permissions, or forged signatures needed.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates every provisioning-behavior disjunct:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to the structurally identical `unarchive?` in [3](#0-2) .

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, add:
```ruby
test "does not create stacks for prevent_with_label repos when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Before the fix: `Shipit::Stack.count` increases by 1 and the created stack's `awaiting_provision?` is `true`, even though `repository.review_stacks_enabled == false`, demonstrating the broken binding. After applying the recommended fix, the assertion passes.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
