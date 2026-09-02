### Title
`provision?` operator-precedence bug bypasses `review_stacks_enabled` master switch, allowing attacker-controlled fork branch to be provisioned as a review stack - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` combines `review_stacks_enabled` with `provisioning_behavior_allow_all?` using `&&`, then `||`s in the `allow_with_label?`/`prevent_with_label?` branches without wrapping the whole expression in parentheses gating on `review_stacks_enabled`. As a result, when a repository has `provisioning_behavior` set to `allow_with_label` (or `prevent_with_label`) but `review_stacks_enabled` is `false` (intended as an off switch), `provision?` still returns `true` whenever the label condition is met, allowing `ReviewStackAdapter#create!` to build a `Shipit::ReviewStack` whose `branch` is the attacker's fork ref.

### Finding Description
Broken binding: `Shipit::Repository#review_stacks_enabled == false` should imply no PR is ever auto-provisioned into a review stack, regardless of `provisioning_behavior`, i.e. `provision? == false` whenever `review_stacks_enabled == false`.

Actual code, [1](#0-0) :
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` binds tighter than `||` in Ruby, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`.

`review_stacks_enabled` only gates the `allow_all?` branch; it is never consulted for the `allow_with_label?` or `prevent_with_label?` branches. So with `review_stacks_enabled = false`, `provisioning_behavior = :allow_with_label`, and the provisioning label present on the PR, `provision?` still evaluates to `true`.

Call path: `OpenedHandler#process` → `respond_to_pull_request_opened?` → `provision?` (bypassed) → `Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` [2](#0-1)  → `ReviewStackAdapter#create!` builds `stack_attributes` with `branch: params.pull_request.head.ref` (the attacker's fork ref, e.g. `pwn/steal-secrets`) and `environment: "pr#{params.number}"`, persists the stack, attaches the PR, and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` [3](#0-2) . Provisioning later checks out that same branch to read the deploy spec/steps.

Existing guards do not block this: signature verification and `ExplicitParameters` schema only validate that the payload is a well-formed GitHub webhook, not that the label-driven provisioning decision honors the master `review_stacks_enabled` switch. The existing test suite only exercises `allow_with_label` with `review_stacks_enabled: true` (the default in `configure_provisioning_behavior`) — [4](#0-3)  — and never exercises the `review_stacks_enabled: false` + `allow_with_label` combination, so the precedence bug is untested and unguarded.

### Impact Explanation
When a maintainer disables review-stack auto-provisioning (`review_stacks_enabled = false`) but has previously configured `provisioning_behavior = allow_with_label` (or `prevent_with_label`) with a label name, the master "off" switch is silently ineffective for those two behaviors. Any pull request satisfying the label condition causes a `Shipit::ReviewStack` to be created and queued for provisioning with `branch` set to the PR author's own head ref — code the maintainer never reviewed. Because review-stack provisioning later checks out that branch's `shipit.yml`/deploy spec and executes its steps via `Command`/`PTY.spawn` on the deploy host, this results in execution of attacker-controlled deploy steps, i.e., unauthorized deploy/RCE on the deploy host — matching the "Critical: unauthorized deploy... via `Command`/`PTY.spawn`" category. It is repeatable against any repository whose owner has this specific stale configuration (`review_stacks_enabled: false` plus `allow_with_label`/`prevent_with_label`), for every PR opened.

### Likelihood Explanation
Exploitation strictly requires the target repository to be in the specific misconfigured state: `provisioning_behavior` set to `allow_with_label` (or `prevent_with_label`) with a label configured, and `review_stacks_enabled` set to `false`. This is a plausible but non-default combination — it can arise if an operator toggles the "enabled" flag off while intending it as a global kill switch, unaware that the boolean logic doesn't honor it for label-based behaviors. Given that state, the only attacker action needed is to open a PR (and, per the scenario's stated attacker capability, apply/have applied the configured label to it). No secrets, tokens, or elevated GitHub permissions are required beyond what's explicitly granted in this exercise's threat model.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the entire decision:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Add regression tests for `review_stacks_enabled: false` combined with `allow_with_label` (label present) and `prevent_with_label` (label absent), asserting no stack is created.

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does not create stacks for repos with review_stacks disabled even when allow_with_label label is present" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # master switch OFF
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }
  payload["pull_request"]["head"]["ref"] = "pwn/steal-secrets"

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Expected (buggy) result: this assertion fails — a stack is created, and `Shipit::ReviewStack.last.branch == "pwn/steal-secrets"` while `repository.review_stacks_enabled == false`, proving `stack.branch` diverges from any maintainer-approved ref for that environment despite the master toggle being off.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
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

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L129-142)
```ruby
          test "creates stacks for repos that allow_with_label when label is present" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :allow_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end
```
