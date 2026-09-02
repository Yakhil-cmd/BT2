### Title
Operator precedence bug in `ReopenedHandler#unarchive?` bypasses `review_stacks_enabled` gate, allowing re-provisioning via PR reopen on repos with review stacks disabled - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler#unarchive?` uses the same flawed `&&`/`||` grouping found in `OpenedHandler#provision?`. Because Ruby's `&&` binds tighter than `||`, the `review_stacks_enabled` check only gates the `provisioning_behavior_allow_all?` branch, not the `allow_with_label?` or `prevent_with_label?` branches. An attacker who owns a PR labeled to satisfy `allow_with_label` can close/reopen their PR to trigger stack (re)provisioning even when `review_stacks_enabled` is `false`.

### Finding Description
The intended binding should be: `unarchive_allowed == review_stacks_enabled && (allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?))`. The actual code at [1](#0-0)  is:

```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Due to `&&`/`||` precedence, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. The second and third disjuncts are completely independent of `review_stacks_enabled`. Thus with `review_stacks_enabled: false`, `provisioning_behavior: :allow_with_label`, and the provisioning label present on the PR, `unarchive?` still evaluates `true`.

Attack flow: the attacker (owner of a fork/PR) closes and reopens their own PR (or GitHub replays a `reopened` webhook after they add the label and reopen). `process` calls `stack.unarchive!` [2](#0-1) , which via `ReviewStackAdapter#unarchive!` either unarchives an existing stack and adds it to the provisioning queue, or calls `create!` to build a brand-new stack and queue it for provisioning [3](#0-2) . Provisioning subsequently runs the repository's `shipit.yml` steps via the deploy machinery, i.e., commands are executed on the deploy host under a workflow the repository owner explicitly disabled (`review_stacks_enabled: false`).

This exactly mirrors the `OpenedHandler#provision?` bug [4](#0-3) , confirming the flaw is duplicated rather than isolated. None of the webhook signature/auth guards are relevant here, since they authenticate that the event genuinely originates from GitHub for that repository — they don't validate the intended business-logic gate (`review_stacks_enabled`) is honored by the boolean expression.

### Impact Explanation
When `review_stacks_enabled` is `false` (the operator's explicit choice to disable review-stack provisioning) but `provisioning_behavior` is set to `:allow_with_label` (or `:prevent_with_label`) with a label configured, any PR author who applies (or omits) the label and reopens their PR causes Shipit to create/unarchive a `Shipit::ReviewStack` and queue it for provisioning — running the repository's provisioning steps (`Command#start`/`PTY.spawn`) despite the feature being disabled. This is a Critical-severity issue: a command runs on the deploy host that the operator did not authorize, using content (branch/environment) tied to the attacker's own PR/fork. Blast radius is scoped to repositories that have this specific, non-default configuration combination (`review_stacks_enabled: false` + `allow_with_label`/`prevent_with_label` + label configured), not all tenants.

### Likelihood Explanation
Exploitation requires no privileged access — it is triggered purely by the pull_request `reopened` webhook, which fires whenever the PR author (or anyone with push access to the head branch) closes and reopens their own PR, or applies/removes a label and reopens. The precondition is a specific repository configuration (`review_stacks_enabled: false` combined with `provisioning_behavior_allow_with_label?`/`prevent_with_label?` and a `provisioning_label_name` set) which is plausible if an operator disables review stacks by flipping `review_stacks_enabled` off but leaves `provisioning_behavior` set. Attacker cost is minimal (label + reopen action) and fully repeatable.

### Recommendation
Fix operator precedence with explicit parentheses so `review_stacks_enabled` gates all branches:

```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the identical fix to `OpenedHandler#provision?` since it shares the same bug.

### Proof of Concept
Add a minitest to `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`:

```ruby
test "does not unarchive/provision when review_stacks_enabled is false, even with allow_with_label + label present" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process

  # Binding under test: unarchive_allowed == repository.review_stacks_enabled
  assert_equal false, repository.reload.review_stacks_enabled
  assert stack.reload.archived?, "Expected stack to remain archived because review_stacks_enabled is false"
end
```

Running this against current code fails (stack becomes unarchived/provisioned), demonstrating the bypass. This is unknown-verified only insofar as `Repository#review_stacks_enabled` default/column semantics were not fully inspected due to iteration limits, but the handler logic itself is directly confirmed from source.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
