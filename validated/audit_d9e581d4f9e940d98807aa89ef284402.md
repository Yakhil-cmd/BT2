### Title
Operator precedence bug in `OpenedHandler#provision?` lets `provisioning_behavior=allow_with_label`/`prevent_with_label` bypass `repository.review_stacks_enabled=false` - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` combines `repository.review_stacks_enabled` with the three provisioning-behavior branches using `&&`/`||` without parentheses, so due to Ruby's `&&` binding tighter than `||`, `review_stacks_enabled` only gates the `allow_all?` branch and is silently dropped from the `allow_with_label?` and `prevent_with_label?` branches. Contrast this with the sibling `LabeledHandler#respond_to_label_change?`, where `review_stacks_enabled` is chained with plain `&&` across the whole expression and correctly gates everything. This means a repository configured with `review_stacks_enabled=false` and `provisioning_behavior=:allow_with_label` will still auto-create and queue-provision a review stack whenever a pull request carries the provisioning label.

### Finding Description
The broken binding, stated as an equality: operators expect `repository.review_stacks_enabled == "true"` to be the sole precondition for any review-stack auto-provisioning on PR open. In code this is: [1](#0-0) 

```
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` binds tighter than `||`, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && label) || (prevent_with_label? && !label)`. `review_stacks_enabled` is parenthesized only with the first disjunct, so when `provisioning_behavior` is `allow_with_label` or `prevent_with_label`, `review_stacks_enabled` has zero effect on the result.

This differs from the sibling handler `LabeledHandler#respond_to_label_change?`, where the same flag is joined with plain `&&` across the full expression and therefore correctly gates all behaviors: [2](#0-1) 

Reachable path: `OpenedHandler#process` calls `respond_to_pull_request_opened?` which is `params.action == "opened" && provision?`, then `ReviewStackAdapter#find_or_create!` on a match: [3](#0-2) 

`ReviewStackAdapter#create!` persists the stack using the attacker-controlled `params.pull_request.head.ref` as `branch` and enqueues it via `ReviewStackProvisioningQueue.add(stack)`: [4](#0-3) 

Separately, `LabelCapturingHandler#capture_labels?` (`opened_active_stack? = opened? && stack.present?`) has no `review_stacks_enabled` check at all and will process once the stack exists: [5](#0-4) 

None of the existing guards prevent this: `params` schema validation only checks shape, not `review_stacks_enabled` semantics; `respond_to_pull_request_opened?` delegates entirely to the flawed `provision?`; and no model validation on `Repository` enforces a relationship between `review_stacks_enabled` and `provisioning_behavior`.

### Impact Explanation
For a repository where an operator sets `review_stacks_enabled=false` (believing it disables all review-stack automation) but leaves `provisioning_behavior=:allow_with_label` (or `:prevent_with_label`) configured, any pull request carrying (or lacking) the provisioning label will still trigger `Shipit::Stack` creation and enter the provisioning queue, whose downstream provisioning task reads `shipit.yml` from the attacker's branch and executes its steps via `Command`/`PTY.spawn` on the deploy host — this is Critical (unauthorized code execution via a gate the operator believed was off). The bug is repeatable for every PR opened against any repository sharing this specific configuration.

### Likelihood Explanation
Requires a specific operator configuration: `review_stacks_enabled=false` combined with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (rather than left at whatever default disables provisioning). Whether such a combination is reachable/likely through the settings UI or only via direct database/console access could not be fully confirmed from the code reviewed — `app/views/shipit/repositories/settings.html.erb` references `provision?` but its form-coupling of `review_stacks_enabled` and `provisioning_behavior` was not inspected in this pass. Once that configuration exists, attacker cost is minimal (open a PR, ensure the label state), and per the audit's threat model the attacker is granted the ability to label their own PR.

### Recommendation
Add explicit parentheses in `OpenedHandler#provision?` so `review_stacks_enabled` gates the entire expression, matching the pattern already used in `LabeledHandler#respond_to_label_change?`:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Also audit `ReopenedHandler`/`UnlabeledHandler` for the same pattern.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb
test "does not create stacks when review_stacks_enabled is false even with allow_with_label and label present" do
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :allow_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Running this against the current implementation of `provision?` fails (a stack IS created), demonstrating that `repository.review_stacks_enabled` is not the enforced gate for the `allow_with_label` branch, confirming the broken equality between the operator-intended gate and the code's actual behavior.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-98)
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

          def environment
            "pr#{params.number}"
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L51-60)
```ruby
          def capture_labels?
            opened_active_stack? ||
              labeled_active_stack? ||
              unlabeled_active_stack? ||
              reopened_active_stack?
          end

          def opened_active_stack?
            opened? && stack.present?
          end
```
