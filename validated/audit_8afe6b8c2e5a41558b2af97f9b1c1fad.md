Confirmed: both `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` share the same operator-precedence defect, while `LabeledHandler#respond_to_label_change?` and `UnlabeledHandler#respond_to_label_change?` correctly gate the whole expression with `repository.review_stacks_enabled && (...)`.

### Title
`OpenedHandler#provision?` fails to gate `allow_with_label`/`prevent_with_label` branches by `repository.review_stacks_enabled`, letting a PR author enqueue a `ReviewStack` for provisioning on a repository with review stacks disabled - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`OpenedHandler#provision?` and `ReopenedHandler#unarchive?` use `a && b || c || d` without parentheses grouping `a` with all of `b`, `c`, `d`. Because `&&` binds tighter than `||` in Ruby, `repository.review_stacks_enabled` is only ANDed with the `allow_all?` branch, so the `allow_with_label` and `prevent_with_label` branches are evaluated independently of `review_stacks_enabled`.

### Finding Description
The intended binding is: `stack.awaiting_provision == true` (and `ReviewStackProvisioningQueue.add` is called) `⟺ repository.review_stacks_enabled == true` at the time `opened`/`reopened` webhooks are processed.

The actual code in `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:65-70`:
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Ruby operator precedence groups this as `(review_stacks_enabled && allow_all?) || (allow_with_label? && label_present) || (prevent_with_label? && !label_present)`. Thus if `review_stacks_enabled` is `false` but `provisioning_behavior` is `allow_with_label` (or `prevent_with_label`), the disabled flag has no effect on those branches. `respond_to_pull_request_opened?` calls `provision?` and, if true, `process` reaches `ReviewStackAdapter#find_or_create!` → `create!`, which unconditionally calls `Shipit::ReviewStackProvisioningQueue.add(stack)` right after `scope.create!(stack_attributes)` with no re-check of `review_stacks_enabled`: [2](#0-1) [3](#0-2) 

The same defect exists in `ReopenedHandler#unarchive?`: [4](#0-3) 

By contrast, `LabeledHandler#respond_to_label_change?` and `UnlabeledHandler#respond_to_label_change?` correctly parenthesize the whole condition (`repository.review_stacks_enabled && (archive? || unarchive?)`), so they are not affected: [5](#0-4) 

**Attacker's request:** any GitHub PR-open (or reopen) webhook for a repository tracked by Shipit whose `provisioning_behavior` is `allow_with_label` (or `prevent_with_label`) but whose `review_stacks_enabled` has been set to `false`. The attacker opens a PR and applies the configured provisioning label (or, for `prevent_with_label`, simply omits it) to their PR — actions available to the PR author on their own fork/PR in the ordinary case, or via the standard `opened`/`labeled`-carrying `pull_request` webhook payload that Shipit ingests.

**Why existing guards don't catch this:** `verify_signature`/webhook auth guards only validate that the payload came from GitHub for the named repository — they do nothing to enforce the `review_stacks_enabled` invariant. The `ExplicitParameters` schema only validates payload shape, not authorization semantics. No model validation on `Shipit::ReviewStack` or `Shipit::Repository` re-checks `review_stacks_enabled` before enqueueing.

### Impact Explanation
For a repository administrator who disabled review-stack automation (`review_stacks_enabled = false`) while leaving `provisioning_behavior` at `allow_with_label`/`prevent_with_label` (e.g., a stale config, or disabled temporarily without also resetting behavior), an unprivileged PR author can still cause Shipit to create a `Shipit::ReviewStack` record and enqueue it via `Shipit::ReviewStackProvisioningQueue.add(stack)`, which ultimately calls `stack.provision`, running real infrastructure-provisioning tasks/commands for that repository. This is a write happening for a repository configuration that explicitly opted out, and it triggers deploy-time task execution (`stack.provision`) that the operator believed was disabled. This matches "Critical — an unauthorized deploy" impact category, since provisioning triggers task execution against the review stack's environment. The blast radius is scoped to the single repository/stack whose config exhibits this combination, and is repeatable for every PR opened/reopened against that repository as long as the misconfiguration persists.

### Likelihood Explanation
Requires a specific repository configuration precondition: `review_stacks_enabled == false` combined with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (not `allow_all`, which is correctly gated). This is a plausible operational state (e.g., an operator toggles `review_stacks_enabled` off without also resetting `provisioning_behavior` to `allow_all`, or the field's default combined with a disable action). Given that precondition, exploitation cost is trivial: open a PR and apply/omit the known provisioning label — no secrets or elevated GitHub permissions beyond what's needed to open a PR and (for many repos) apply a label to it.

### Recommendation
Fix the boolean grouping in both `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` to gate all behavior branches on `review_stacks_enabled`:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the analogous fix to `ReopenedHandler#unarchive?`.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does NOT create/provision stacks when review_stacks_enabled is false, even with allow_with_label and label present" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # review_stacks_enabled == false
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  Shipit::ReviewStackProvisioningQueue.expects(:add).never  # binding: enabled == false => add never called

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Running this against current code fails: `Shipit::ReviewStackProvisioningQueue.add` is called and a `Shipit::Stack` is created, demonstrating `repository.review_stacks_enabled == false` while `stack.awaiting_provision == true` — the broken binding.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```
