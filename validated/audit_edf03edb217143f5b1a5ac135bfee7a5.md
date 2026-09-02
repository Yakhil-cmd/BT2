This confirms the vulnerability. `create!` writes a `ReviewStack` (subclass of `Shipit::Stack`) via `scope.create!(stack_attributes)` and enqueues it into `Shipit::ReviewStackProvisioningQueue` regardless of `review_stacks_enabled`, since `provision?` already returned true incorrectly. [1](#0-0) 

### Title
`provision?` operator-precedence bug bypasses `review_stacks_enabled` gate for the `prevent_with_label` behavior - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` combines `review_stacks_enabled` with the three provisioning-behavior checks using Ruby's default `&&`/`||` precedence, so `review_stacks_enabled` only gates the `allow_all` clause. The `allow_with_label` and `prevent_with_label` clauses are evaluated independently of `review_stacks_enabled`, letting an attacker provision a review stack on a repository that has review stacks disabled.

### Finding Description
The broken binding: the code intends `review_stacks_enabled == true` to gate every provisioning path, but the actual gate applied to `prevent_with_label?` path is `review_stacks_enabled == false` (irrelevant) rather than `true`.

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [2](#0-1) 

Because `&&` binds tighter than `||`, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. Only the first disjunct is protected by `review_stacks_enabled`; the second and third are not. With `review_stacks_enabled == false` and `provisioning_behavior == :prevent_with_label`, opening an unlabeled PR makes `prevent_with_label?` true and `!has_label?` true, so `provision?` returns `true` even though review stacks are disabled for that repository.

Attacker action: any unprivileged GitHub user who can open a pull request against the target repository opens a PR with no labels. GitHub emits a `pull_request` `opened` webhook, handled by `OpenedHandler#process`, which calls `respond_to_pull_request_opened?` → `provision?` (true per the flaw) → `ReviewStackAdapter#find_or_create!` → `create!`, which does `scope.create!(stack_attributes)` writing a new `Shipit::ReviewStack`/`Stack` row and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)`. [3](#0-2) [1](#0-0) 

Existing guards do not catch this: webhook signature verification only authenticates that GitHub sent the payload, not that the PR is entitled to provision; `Repository#review_stacks_enabled` and the `provisioning_behavior` enum are legitimate configuration values, and the params schema validates payload shape but not the business-logic gating. None of these prevent the operator-precedence divergence. [4](#0-3) 

### Impact Explanation
Any GitHub user who can open a PR on a repository configured with `review_stacks_enabled: false` and `provisioning_behavior: prevent_with_label` can force Shipit to create and provision a `ReviewStack`/`Stack` record for that repository — a write that should never happen since review stacks are explicitly disabled. This is repeatable per PR/branch and constitutes an unauthorized deploy-stack creation and provisioning trigger, matching the Critical category ("a payload... mutating another's stack... or an unauthorized deploy"). Blast radius is scoped to repositories using this exact configuration combination, but is fully repeatable by any contributor able to open PRs against that repo.

### Likelihood Explanation
Preconditions are pure repository configuration (`review_stacks_enabled == false`, `provisioning_behavior == :prevent_with_label`) which is realistic — an operator disabling review stacks while leaving provisioning_behavior at `prevent_with_label` (a plausible default/leftover setting). Attacker cost is trivial: open an unlabeled PR, no secrets, no privileges, no special access needed. Fully reproducible via webhook replay.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates all three clauses:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

### Proof of Concept
In a minitest (e.g. `opened_handler_test.rb`-style test), create a `Shipit::Repository` with `review_stacks_enabled: false` and `provisioning_behavior: "prevent_with_label"`, build an `opened` pull_request payload with `pull_request.labels = []`, invoke the handler's `process`, and assert:
```ruby
assert_no_difference -> { Shipit::Stack.count } do
  Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(params).process
end
```
Before the fix this assertion fails because `Shipit::Stack.count` increases by 1 (a `ReviewStack` is created via `ReviewStackAdapter#create!`); after applying the recommended fix, `provision?` returns `false` and the assertion passes.

### Citations

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

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
```
