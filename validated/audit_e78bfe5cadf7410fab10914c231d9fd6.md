### Title
`OpenedHandler#provision?` third disjunct bypasses `review_stacks_enabled` due to operator precedence - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`provision?` is written as `A && B || (C && D) || (E && F)`, and Ruby's `&&`/`||` precedence means only the first disjunct is gated by `repository.review_stacks_enabled`. When `provisioning_behavior=:prevent_with_label` and the PR carries no provisioning label, the third disjunct `(repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)` evaluates `true` regardless of `review_stacks_enabled`, letting an unprivileged PR author trigger review-stack creation and provisioning on a repository where the feature is disabled.

### Finding Description
The broken binding: the code should enforce `review_stacks_enabled == true` for *every* provisioning path, but as written it only enforces `review_stacks_enabled == true` for the `allow_all` branch:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Because `&&` binds tighter than `||`, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)`. The second and third disjuncts have no dependency on `review_stacks_enabled` at all.

Attack: attacker opens a PR against a repo configured with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false`, and simply does not attach the provisioning label (the default state of any new PR). `provisioning_behavior_prevent_with_label?` is `true` and `!pull_request_has_provisioning_label?` is `true`, so `provision?` returns `true` even though `review_stacks_enabled` is `false`.

`process` then calls `respond_to_pull_request_opened?` which returns true [2](#0-1) [3](#0-2) , and `ReviewStackAdapter#find_or_create!` creates a `ReviewStack` scoped to `repository.review_stacks` (the scope itself carries no `review_stacks_enabled` gate) and enqueues it for provisioning via `Shipit::ReviewStackProvisioningQueue.add(stack)` [4](#0-3) . `ReviewStackProvisioningQueue#provision` checks only `stack.provisioner.provision?`, and the default `ProvisioningHandler::Base#provision?` returns `true` unconditionally [5](#0-4) , so nothing downstream re-checks `review_stacks_enabled`. The `ReviewStack` state machine then fires `stack.provisioner.up` on the `deprovisioned -> provisioning` transition [6](#0-5) , which for real deployments runs the attacker-controlled `shipit.yml` steps from the PR's branch/commit. No existing guard (webhook signature verification, `ExplicitParameters` schema, or model validations) checks `review_stacks_enabled` anywhere in this path — the feature flag is simply not consulted for the `prevent_with_label` and `allow_with_label` behaviors.

### Impact Explanation
This is Critical: it results in execution of steps taken from an attacker-controlled `shipit.yml`/branch on the deploy host via the provisioning/task machinery, for a repository whose maintainer explicitly disabled review stacks (`review_stacks_enabled=false`). Any repository configured with `provisioning_behavior: prevent_with_label` (a legitimate, documented configuration meant to require an opt-out label) is vulnerable purely from an unprivileged PR with no label, independent of the `review_stacks_enabled` toggle. This is repeatable per PR/per repository that uses this behavior, and affects only repos with this specific config combination, but for those repos it is a full authentication-bypass-equivalent (bypassing the "review stacks enabled" authorization gate).

### Likelihood Explanation
Preconditions: repository must have `provisioning_behavior: prevent_with_label` configured (a supported, documented setting) and `review_stacks_enabled: false`. No secrets, tokens, or privileged roles are needed — attacker only needs to open a PR with no labels, which is the default state of any PR they create in their own fork/branch. Cost is minimal (a single PR open action) and the bug is deterministic/repeatable on every PR opened against such a repo.

### Recommendation
Fix operator grouping so `review_stacks_enabled` gates all three disjuncts, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
minitest plan in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
1. Create a `Shipit::Repository` with `review_stacks_enabled: false` and `provisioning_behavior: "prevent_with_label"`.
2. Build a webhook payload for `action: "opened"` with `pull_request.labels: []` (no provisioning label) against that repository.
3. Instantiate `OpenedHandler` with the payload and call `#process`.
4. Assert equality on both sides of the binding: `repository.review_stacks_enabled` is `false` while the handler's actual gating condition (`provision?` result) is `true` — assert `Shipit::ReviewStack.where(environment: "pr#{number}").exists?` is `true` and that `ReviewStackProvisioningQueue`/`awaiting_provision` was set, demonstrating the mismatch between the declared `review_stacks_enabled=false` and the de-facto provisioning that occurred.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-63)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
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

**File:** app/models/shipit/provisioning_handler/base.rb (L18-23)
```ruby
      # An (optional) guard to prevent provisioning. Intended to be
      # use to set logic to determine if enough actual resources exist
      # to complete the provisioning request.
      def provision?
        true
      end
```

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
      end
```
