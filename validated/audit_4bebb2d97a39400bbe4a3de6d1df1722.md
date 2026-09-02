Confirmed. The precedence bug is real and reachable exactly as the question describes.### Title
`OpenedHandler#provision?` / `ReopenedHandler#unarchive?` bypass `review_stacks_enabled` via `&&`/`||` operator precedence when `provisioning_behavior` is label-based - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` and the structurally identical `ReopenedHandler#unarchive?` intend to gate all ReviewStack creation/unarchival on `repository.review_stacks_enabled`, but because `&&` binds tighter than `||` in Ruby, `review_stacks_enabled` is only ANDed with the `provisioning_behavior_allow_all?` branch. The `allow_with_label` and `prevent_with_label` branches are OR'd in unconditionally, so when a repository is configured with a label-based provisioning behavior and `review_stacks_enabled: false`, `provision?`/`unarchive?` still evaluate to `true`. This lets an unprivileged fork contributor cause `ReviewStack` creation for a repository whose operator explicitly disabled review stacks.

### Finding Description
The broken binding is: `repository.review_stacks_enabled == true` must hold for any `ReviewStack` row to be created for that repository, per the model/feature intent (and confirmed by `LabeledHandler#respond_to_label_change?`, which correctly ANDs `repository.review_stacks_enabled` across the entire `(archive? || unarchive?)` expression at [1](#0-0) ). In `OpenedHandler`, the same guard is written as:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [2](#0-1) 

Due to Ruby operator precedence, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. `review_stacks_enabled` is not combined with the second and third disjuncts at all. The identical pattern exists in `ReopenedHandler#unarchive?` [3](#0-2) .

Exploit path: an unprivileged GitHub user opens a normal pull request from a fork against a target repository configured with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false` (an operator-set configuration meant to disable review-stack automation). GitHub sends a legitimate, correctly-signed `pull_request` "opened" webhook. `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler#process` calls `respond_to_pull_request_opened?` → `provision?` [4](#0-3) . Since a fresh PR has no labels by default, `pull_request_has_provisioning_label?` is `false`, so `prevent_with_label? && !false` evaluates `true`, making `provision?` return `true` despite `review_stacks_enabled == false`. `ReviewStackAdapter#find_or_create!` then calls `#create!`, which creates a `ReviewStack` row with `environment: "pr#{number}"` and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` [5](#0-4) , driving the stack's `provision` state machine transition which invokes `stack.provisioner.up` [6](#0-5) , i.e., real provisioning work is scheduled for a repository whose operator disabled review stacks. Each additional non-labeled fork PR reproduces this identically and independently — it is systemic, not a one-off.

Existing guards do not prevent this: webhook signature verification only authenticates that GitHub sent the payload, not that the *content* of an ordinary PR-open action should be permitted to bypass `review_stacks_enabled`; `ExplicitParameters` validates payload shape, not authorization semantics; and no model validation ties `ReviewStack` creation to `review_stacks_enabled`. The only enforcement point is this Ruby boolean expression, which is broken by precedence.

### Impact Explanation
Any unauthenticated/unprivileged fork contributor can force creation and provisioning-queue enqueueing of a `ReviewStack` (and its underlying deploy/provisioning workflow) for a target repository that the operator explicitly configured to have review stacks *disabled*, as long as `provisioning_behavior` is `allow_with_label` or `prevent_with_label`. This results in unauthorized provisioning being triggered for a repository against the operator's explicit configuration — an unauthorized deploy/provisioning action taken on behalf of a repository that did not consent to it via its `review_stacks_enabled` setting. This is repeatable for every affected repository and every new PR (or PR reopen), and does not require any secret, session, or elevated GitHub permission.

### Likelihood Explanation
Preconditions: target repository has `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` and `review_stacks_enabled: false`. Attacker cost is trivial — simply opening (or reopening) a pull request from a fork with no special label, which any GitHub user permitted to open PRs against the repo can do. No secrets, sessions, tokens, or team membership are required. The scenario is fully feasible and directly reachable via normal GitHub webhook delivery.

### Recommendation
Fix operator precedence by parenthesizing the intended grouping in `OpenedHandler#provision?` and `ReopenedHandler#unarchive?`:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to `ReopenedHandler#unarchive?`.

### Proof of Concept
```ruby
test "does not create or provision a review stack when review_stacks_enabled is false, even with prevent_with_label behavior and no label" do
  repository = shipit_repositories(:shipit)
  repository.update!(
    review_stacks_enabled: false,
    provisioning_behavior: :prevent_with_label,
    provisioning_label_name: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  # Binding under test: repository.review_stacks_enabled == true is required
  # for any ReviewStack row to exist for repository.id.
  assert_equal false, repository.review_stacks_enabled

  assert_no_difference -> { Shipit::ReviewStack.where(stack_id: repository.stacks.pluck(:id)).count } do
    OpenedHandler.new(payload).process
  end
end
```
This test currently fails against the shipped code (a `ReviewStack` row is created despite `review_stacks_enabled == false`), demonstrating the divergence between the intended binding and actual behavior.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
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

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
      end
```
