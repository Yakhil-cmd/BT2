## Finding confirmed

The claimed binding — `repository.review_stacks_enabled == true` as a precondition for any `ReviewStack` row to exist for that repository — is **not enforced** for two of the four PR-event handlers due to a Ruby operator-precedence bug.

### Root cause

In `OpenedHandler#provision?`:
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

`&&` binds tighter than `||` in Ruby, so this is actually evaluated as:

`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

`review_stacks_enabled` is only ANDed into the `allow_all?` branch. For the `allow_with_label` and `prevent_with_label` branches, `review_stacks_enabled` is never checked. The identical bug exists in `ReopenedHandler#unarchive?`: [2](#0-1) 

By contrast, `LabeledHandler#respond_to_label_change?` correctly ANDs `review_stacks_enabled` across the *entire* condition: [3](#0-2) 
so `LabeledHandler`/`UnlabeledHandler` are not affected — only `OpenedHandler` and `ReopenedHandler`.

### Exploit path

`OpenedHandler#process` → `provision?` → `ReviewStackAdapter#find_or_create!` → `create!` creates a `ReviewStack` row and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)`, which will invoke the host's `ProvisioningHandler#up` for that stack: [4](#0-3) [5](#0-4) 

If a repository has `review_stacks_enabled = false` but `provisioning_behavior = prevent_with_label` (or `allow_with_label`), an unprivileged attacker who can merely **open a pull request** against that public repo (no label needed for the `prevent_with_label` default no-label case) causes `provision?`/`unarchive?` to evaluate true, and a `ReviewStack` is created and queued for provisioning — despite the repository owner explicitly disabling review stacks in the UI.

The existing test suite does not cover this combination: `opened_handler_test.rb`'s `configure_provisioning_behavior` defaults `provisioning_enabled: true` for all `allow_with_label`/`prevent_with_label` tests, so this gap was never exercised. [6](#0-5) 

### Why this matters

`review_stacks_enabled` is meant to be a hard gate an operator sets in the repository settings UI: [7](#0-6) 
The bug lets any user capable of opening/reopening a PR against the target repo bypass that gate whenever `provisioning_behavior` is left at `allow_with_label` or `prevent_with_label` (regardless of the `review_stacks_enabled` toggle), causing repeated, unauthorized `ReviewStack` row creation and provisioning-handler invocation (`up`) for every such PR — a systemic issue, not a one-off, matching the scoped impact described.

### Recommendation
Fix the operator precedence so `review_stacks_enabled` gates all three branches, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to `ReopenedHandler#unarchive?`.

### Proof of Concept (minitest sketch)
```ruby
test "does not create stacks when review_stacks_enabled is false, even with prevent_with_label and no label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  assert_no_difference -> { Shipit::ReviewStack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Running this against current code fails (a `ReviewStack` is created), demonstrating the bypass of the `review_stacks_enabled == false` binding.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
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

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
      end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L159-187)
```ruby
          test "create stacks for repos what prevent_with_label when label is absent" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] = []

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end

          test "does not create stacks for repos what prevent_with_label when label is present" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end
```

**File:** docs/review_stacks.md (L9-13)
```markdown
1. Visit the shipit-engine Repository UI - `https://host-application/repositories`
1. Click on the project's repository
1. Check "Dynamically provision stacks for Pull Requests?"
1. Select the "Provisioning Behavior" appropriate for your project - most likely "Allow All"
1. Click "Save"
```
