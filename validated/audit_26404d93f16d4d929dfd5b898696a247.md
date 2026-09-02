Confirmed: the only test with `provisioning_enabled: false` in `opened_handler_test.rb` uses `behavior: :allow_all`, and there is no test exercising `provisioning_enabled: false` combined with `allow_with_label`/`prevent_with_label`. This is exactly the untested gap where the operator-precedence bug manifests.

### Title
`ReopenedHandler#unarchive?` and `OpenedHandler#provision?` ignore `review_stacks_enabled` for label-based provisioning behaviors due to `&&`/`||` operator precedence - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler#unarchive?` (and identically `OpenedHandler#provision?`) writes `repository.review_stacks_enabled && repository.provisioning_behavior_allow_all? || (...allow_with_label...) || (...prevent_with_label...)`. Because `&&` binds tighter than `||` in Ruby, `review_stacks_enabled` only gates the `allow_all` branch; the `allow_with_label` and `prevent_with_label` branches are evaluated independently of `review_stacks_enabled`. `LabeledHandler#respond_to_label_change?`, by contrast, correctly ANDs `repository.review_stacks_enabled` across the whole `(archive? || unarchive?)` expression, showing the intended semantics.

### Finding Description
The broken binding: `repository.review_stacks_enabled == the flag that should gate all re-provisioning branches` is false as written; the actual code only evaluates `repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?` as one term, then independently ORs in `(repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?)` and `(repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)` with no reference to `review_stacks_enabled` at all: [1](#0-0) 

The identical pattern exists in `OpenedHandler#provision?`: [2](#0-1) 

Compare to the correct pattern in `LabeledHandler#respond_to_label_change?`, which ANDs `repository.review_stacks_enabled` over the entire `(archive? || unarchive?)` disjunction: [3](#0-2) 

Call path: `ReopenedHandler#process` calls `respond_to_pull_request_reopened?`, which calls `unarchive?`; if `repository.provisioning_behavior_allow_with_label?` is true and the PR carries the label, `unarchive?` returns `true` regardless of `review_stacks_enabled`. `process` then calls `stack.unarchive!` on the `ReviewStackAdapter`, which — since `stack.archived?` is true for a previously archived `pr#{number}` `ReviewStack` — calls `Shipit::ReviewStackProvisioningQueue.add(stack)` and `stack.unarchive!`: [4](#0-3) 

This re-enqueues provisioning, which eventually spawns the deploy-time task (`TaskCommands#perform` → `Command#start` → `PTY.spawn`) against `stack.branch`, which is attacker-controlled (`params.pull_request.head.ref` set at stack creation and updatable by any push to the PR's head branch, since the attacker owns the fork/branch).

None of the existing guards intervene: `params` validation only checks payload shape, not `review_stacks_enabled`; `pull_request_has_provisioning_label?` only checks label membership from attacker-controlled payload data; and there is no code path re-checking `review_stacks_enabled` before `ReviewStackAdapter#unarchive!`/`ReviewStackProvisioningQueue.add`.

### Impact Explanation
An unprivileged PR author on a repository where `review_stacks_enabled` has been disabled after a review stack was archived can still trigger re-provisioning (unarchiving) of the stack by reopening the PR (or, symmetrically, initial provisioning via `OpenedHandler`), as long as `provisioning_behavior` is `allow_with_label`/`prevent_with_label` and the label condition is met. Since the PR author fully controls the head branch content and `shipit.yml`, this results in execution of attacker-controlled commands via `Command`/`PTY.spawn` on a repository whose operators explicitly turned off review-stack provisioning — a Critical impact (RCE on the deploy host) scoped to the repository that has this specific misconfiguration (label-based behavior + review stacks disabled + a prior/archived stack).

### Likelihood Explanation
Requires a specific but plausible repository configuration: `provisioning_behavior` set to `allow_with_label` (label present on PR) or `prevent_with_label` (label absent), and `review_stacks_enabled` toggled off — a state reachable if an operator disables review stacks without changing `provisioning_behavior`, or disables it while a stack from before is still archived. No secrets or privileged access needed; the attacker only needs an open PR against the target repo with control over labels they can add themselves (if they are a collaborator) or via a fork PR with default label state matching `prevent_with_label`. This is repeatable per PR/branch.

### Recommendation
Fix operator precedence to have `review_stacks_enabled` gate the entire expression, matching `LabeledHandler`'s pattern, e.g.:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to `OpenedHandler#provision?`.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`, add a test that:
1. Creates an archived stack via `create_archived_stack`.
2. Calls `configure_provisioning_behavior(repository:, provisioning_enabled: false, behavior: :allow_with_label, label: "pull-requests-label")` (setting `repository.review_stacks_enabled = false`).
3. Builds `payload = payload_parsed(:pull_request_reopened)` and appends the label `{"name" => "pull-requests-label"}` to `payload["pull_request"]["labels"]`.
4. Calls `Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process`.
5. Asserts the binding is violated: `assert_equal false, Shipit::Repository.find(repository.id).review_stacks_enabled` (left side) while `assert_not stack.reload.archived?, "Expected stack to remain archived because review_stacks_enabled is false"` fails (right side shows it was unarchived) — i.e. assert `stack.reload.archived?` is `false` and `assert_pending_provision(stack)` succeeds, demonstrating re-provisioning occurred despite `review_stacks_enabled == false`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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
