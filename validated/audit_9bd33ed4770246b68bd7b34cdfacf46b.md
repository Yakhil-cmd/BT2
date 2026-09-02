### Title
`OpenedHandler#provision?` bypasses `review_stacks_enabled` for the `prevent_with_label` behavior - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` uses `&&`/`||` in a way that only gates the `allow_all` branch behind `repository.review_stacks_enabled`; the `prevent_with_label` branch (and the `allow_with_label` branch) are evaluated independently of that flag. An attacker opening an unlabeled PR against a repository configured with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false` can still trigger review-stack creation and provisioning.

### Finding Description
The claimed binding is: `review_stacks_enabled == the gate applied to every provisioning branch`. In the actual code this binding is broken: [1](#0-0) 

Due to Ruby operator precedence (`&&` binds tighter than `||`), the expression parses as:

```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)
```

The `review_stacks_enabled` flag is ANDed only with `allow_all?`. It has no effect on the `allow_with_label?` or `prevent_with_label?` branches. So for a repository with `provisioning_behavior_prevent_with_label? == true` and `review_stacks_enabled == false`, `provision?` still evaluates to `true` whenever the PR has no matching label (`!pull_request_has_provisioning_label?`).

Attacker's PR: open a pull request from a fork (or a branch in an owned repo that's tracked by Shipit with `prevent_with_label` behavior) with no labels attached. `process` calls `respond_to_pull_request_opened?` → `provision?` → `true`, then invokes `ReviewStackAdapter#find_or_create!` → `create!`, which persists a `Stack` record with `branch: params.pull_request.head.ref` and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)`: [2](#0-1) 

This queued stack later gets provisioned, running the deploy spec (`shipit.yml`) taken from the attacker-controlled branch — despite the repository explicitly having `review_stacks_enabled == false` (i.e., review stacks were never turned on for that repo).

No downstream check re-validates `review_stacks_enabled` before `create!`/`Shipit::ReviewStackProvisioningQueue.add`, so nothing catches this divergence.

Note: `LabeledHandler#respond_to_label_change?` correctly ANDs `review_stacks_enabled` with the entire `archive?/unarchive?` decision (`repository.review_stacks_enabled && (archive? || unarchive?)`), confirming the intended design was for `review_stacks_enabled` to gate *all* behaviors, not just `allow_all`: [3](#0-2) 

This inconsistency confirms `OpenedHandler#provision?` (and its sibling `ReopenedHandler`, which has an identical `provision?` implementation) has the wrong precedence/grouping.

### Impact Explanation
On any repository tracked by Shipit with `provisioning_behavior = prevent_with_label` but `review_stacks_enabled = false` (a configuration meant to keep review-stack auto-provisioning off), an unprivileged attacker who can open a PR without the exclusion label causes: a new `Shipit::Stack` (review stack) to be created and queued for provisioning, and eventually deployed/executed via the repository's `shipit.yml` from the attacker's branch. This is unauthorized stack creation and command execution on a repository that never opted into review stacks — matching the Critical category "a payload for one repository mutating another's [config/expectation]" / "an unauthorized deploy". It's repeatable for every PR opened against any such misconfigured (but plausible/real) repository.

### Likelihood Explanation
Preconditions: the target `Repository` row must exist in Shipit with `provisioning_behavior = prevent_with_label` and `review_stacks_enabled = false`. This is a legitimate, documented combination an operator could set (e.g., intending "don't auto-provision unless labeled 'skip-review'" is expected to require review stacks to be explicitly enabled first, or an admin disables review stacks while leaving `provisioning_behavior` set to `prevent_with_label` from a prior configuration). The attacker needs no privileges beyond opening a PR without the label — trivial and repeatable at will.

### Recommendation
Fix operator grouping in `provision?` (and the identical logic in `ReopenedHandler`) so `review_stacks_enabled` gates all three behaviors, e.g.:

```ruby
def provision?
  repository.review_stacks_enabled &&
    (
      repository.provisioning_behavior_allow_all? ||
      (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
      (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
    )
end
```

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

Assert both sides of the binding: before the fix, `repository.review_stacks_enabled == false` while `OpenedHandler.new(payload).send(:provision?) == true` (divergence, test fails/creates a stack); after applying the recommended fix, `provision? == false` and the `assert_no_difference` passes.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```
