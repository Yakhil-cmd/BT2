### Title
Missing `review_stacks_enabled` check in `LabelCapturingHandler` allows cross-policy PullRequest mutation via `OpenedHandler#provision?` precedence bug - (File: app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`OpenedHandler#provision?` has an operator-precedence bug that lets a `ReviewStack` be provisioned for `pr#{number}` even when `repository.review_stacks_enabled == false`, as long as `provisioning_behavior` is `:allow_with_label` or `:prevent_with_label`. `LabelCapturingHandler` then trusts `stack.present?` alone (never re-checking `review_stacks_enabled`) and calls `pull_request.update!(labels: ...)` on that stack's `PullRequest`, mutating a record for a repository that explicitly opted out of review stacks.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == true` for any repository whose `ReviewStack` `pull_request` row is mutated by `LabelCapturingHandler`. Tracing the code shows this binding is broken.

`OpenedHandler#provision?` is:
```ruby
repository.review_stacks_enabled &&
  repository.provisioning_behavior_allow_all? ||
  (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
  (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
``` [1](#0-0) 

Due to Ruby `&&`/`||` precedence, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. Only the first disjunct is gated by `review_stacks_enabled`; the second and third are not. For a repository with `provisioning_behavior: :prevent_with_label` and `review_stacks_enabled: false`, sending a webhook `action: "opened"` with `pull_request.head.ref = "exploit-branch"` and no provisioning label satisfies `provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?`, so `provision?` returns `true` and `respond_to_pull_request_opened?` triggers `ReviewStackAdapter#find_or_create!`, which creates a real `Shipit::ReviewStack` (`environment: "pr#{params.number}"`, `branch: params.pull_request.head.ref`) and a `PullRequest` row via `build_pull_request.update!(github_pull_request: params.pull_request)` [2](#0-1) , despite `review_stacks_enabled == false`.

A second webhook, `action: "labeled"` adding an arbitrary label, reaches `LabelCapturingHandler`. Its gate is:
```ruby
def capture_labels?
  opened_active_stack? || labeled_active_stack? || unlabeled_active_stack? || reopened_active_stack?
end

def labeled_active_stack?
  labeled? && stack.present? && !stack.archived?
end
``` [3](#0-2) 

None of `capture_labels?`'s branches check `repository.review_stacks_enabled`; they only check `stack.present?` (found via `repository.review_stacks.find_by(environment: "pr#{number}")`, an association that itself is not filtered by `review_stacks_enabled`) [4](#0-3) . Since the stack from step one exists and is not archived, `capture_labels` executes:
```ruby
def capture_labels
  return unless pull_request = stack.pull_request
  pull_request.update!(labels: params.pull_request.labels.map(&:name))
end
``` [5](#0-4) 

This mutates a `PullRequest` record tied to a repository/stack that `review_stacks_enabled` was supposed to prevent from ever being created or touched. No guard in `LabelCapturingHandler`, `ReviewStackAdapter`, or `Repository` re-validates `review_stacks_enabled` at write time — the check exists only (partially, buggily) in `OpenedHandler#provision?`.

Both webhook requests only require `verify_signature`/webhook-secret validation at the controller boundary (not part of this vulnerability class per the audit scope — this is a same-repo, attacker-owns-the-PR scenario, not a forged-signature scenario) and `ExplicitParameters` schema conformance, both of which are satisfied by a normal PR the attacker opens on their own fork/branch with labels they control. No authentication bypass is required beyond the attacker's own GitHub webhook events for their own PR against the target repository.

### Impact Explanation
The attacker (an unprivileged contributor able to open a PR and add labels on their own fork against the target repo) can force creation of a `Shipit::ReviewStack` and its associated `PullRequest` row, and subsequently mutate `PullRequest.labels`, for a repository whose administrators explicitly disabled review stacks (`review_stacks_enabled = false`). This is a policy-write bypass: state is created and mutated in the database that the repository owner opted out of. This matches the "record written for a repository that did not authenticate it" / cross-repository-policy-write category. It does not, by itself, achieve `PTY.spawn`/RCE or credential exfiltration, but it is a repeatable, unauthorized data-mutation primitive per attacker-controlled PR/repo, and it also causes a provisioning queue side effect (`Shipit::ReviewStackProvisioningQueue.add(stack)`), which is out of scope here (DoS/resource) but corroborates unintended stack provisioning.

### Likelihood Explanation
Preconditions: target repository must have `provisioning_behavior` set to `:allow_with_label` or `:prevent_with_label` and `review_stacks_enabled: false` — a plausible, even encouraged, configuration for repos transitioning away from review stacks while retaining label-based provisioning rules elsewhere. Attacker cost is minimal: open a PR from a fork, then add/have a label on it — both standard, unprivileged GitHub actions that any contributor can perform, triggering the two webhooks Shipit already expects to receive. It is repeatable against any repository matching this configuration.

### Recommendation
Fix `OpenedHandler#provision?` operator precedence so `repository.review_stacks_enabled` gates all three disjuncts, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Additionally, defensively re-check `repository.review_stacks_enabled` in `LabelCapturingHandler#capture_labels?` (and `LabeledHandler`/`UnlabeledHandler`/`ReopenedHandler`) so no handler acts on a stack for a repository with review stacks disabled, independent of how the stack was created.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/label_capturing_handler_test.rb` (existing suite location):
1. Create a `Shipit::Repository` fixture with `review_stacks_enabled: false`, `provisioning_behavior: "prevent_with_label"`.
2. Directly instantiate/insert a `Shipit::ReviewStack` for `environment: "pr123"` (simulating the state produced by the `OpenedHandler#provision?` bug) with a `PullRequest` child having `labels: []`.
3. Build `params` for a `"labeled"` action, `number: 123`, `pull_request.labels: [{name: "arbitrary-label"}]`, `repository.full_name` matching the fixture.
4. Run `LabelCapturingHandler.new(...).process` (or invoke via the handler entrypoint used elsewhere in the test file).
5. Assert binding both sides: before, `repository.review_stacks_enabled == false`; after running the handler, assert `pull_request.reload.labels == []` (unchanged) — currently this assertion fails because `pull_request.labels` becomes `["arbitrary-label"]`, proving the write occurred despite `review_stacks_enabled == false`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L51-64)
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

          def labeled_active_stack?
            labeled? && stack.present? && !stack.archived?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/repository.rb (L47-48)
```ruby
    has_many :stacks, dependent: :destroy
    has_many :review_stacks, dependent: :destroy
```
