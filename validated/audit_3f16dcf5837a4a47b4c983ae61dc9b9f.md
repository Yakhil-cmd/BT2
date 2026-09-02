### Title
`review_stacks_enabled` flag is not honored for `allow_with_label`/`prevent_with_label` provisioning behaviors - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` only ANDs `repository.review_stacks_enabled` against the `allow_all` branch of the `||` chain; the `allow_with_label` and `prevent_with_label` branches are evaluated independently of that flag. For a repository with `review_stacks_enabled == false`, setting `provisioning_behavior` to `allow_with_label` (and labeling the PR) or `prevent_with_label` (and not labeling the PR) still causes a review stack to be created and provisioned.

### Finding Description
Binding claimed vs. actual: the operator expects `review_stacks_enabled == false` ⇒ `provision? == false` for **all** values of `provisioning_behavior`. The actual code is: [1](#0-0) 

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Due to Ruby operator precedence (`&&` binds tighter than `||`), this parses as:
```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)
```
So `review_stacks_enabled` only gates the first disjunct. For `review_stacks_enabled == false, provisioning_behavior == :allow_with_label`: `(false && false) || (true && has_label?) || (false && ...)` → `provision?` returns `has_label?`'s value, i.e., `true` whenever the PR carries the provisioning label — completely independent of `review_stacks_enabled`. Similarly for `prevent_with_label`.

Attacker path: an unprivileged GitHub user opens a pull request against a repository whose Shipit `Repository` record has `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label` (or `prevent_with_label`). The attacker labels their own PR (or simply does nothing, for `prevent_with_label`) and the `opened` webhook fires. `respond_to_pull_request_opened?` → `provision?` returns true, and `ReviewStackAdapter#find_or_create!` creates a `ReviewStack` and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)`, which drives the provisioning pipeline (`ProvisioningHandler` → deploy/provision commands ultimately reaching `Command#start`/`PTY.spawn`) even though the repository owner explicitly disabled review-stack provisioning.

None of the existing guards intercept this: webhook signature verification (`verify_signature`) only authenticates that GitHub sent the payload, not that provisioning should occur; the `ExplicitParameters` schema only validates payload shape; and there is no other `review_stacks_enabled` check downstream in `ReviewStackAdapter#create!` or `ProvisioningHandler::Base#provision?` (which defaults to `true`). The flag is checked in exactly one place, and only for one of the three behavior branches.

### Impact Explanation
For any repository configured this way, an unprivileged actor able to open a PR and set a label on it (or merely open a PR, for `prevent_with_label`) causes Shipit to create and provision a review stack, running the repository's provisioning pipeline (deploy/build commands executed by `Command#start`) against attacker-controlled branch content, despite the operator having disabled review stacks (`review_stacks_enabled: false`) as an explicit safety switch. This is repeatable per PR and matches the Critical category (RCE on the deploy host via the provisioning/deploy command pipeline triggered without proper authorization).

### Likelihood Explanation
Requires a repository configured with `review_stacks_enabled: false` and `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` — a plausible transitional/misconfiguration state (e.g., operator toggling `review_stacks_enabled` off temporarily without also resetting `provisioning_behavior` to `allow_all`, since the UI/model treats these as independent settings). No secrets or elevated privileges are needed; the attacker only needs to open a PR (and optionally apply a label they control) from a fork. Cost is trivial and fully repeatable.

### Recommendation
Gate all three branches uniformly, e.g.:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

### Proof of Concept
minitest test (conceptually, per the existing test suite pattern in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
1. Build/stub a repository double with `review_stacks_enabled = false`.
2. For each `provisioning_behavior` in `%w[allow_all allow_with_label prevent_with_label]`, set the corresponding predicate methods and simulate PR label presence/absence to satisfy each branch's positive condition.
3. Assert equality: `assert_equal false, handler.send(:provision?)` for all three combinations.
4. Current code fails this assertion for `allow_with_label` (with label present) and `prevent_with_label` (with label absent), while passing only for `allow_all`, demonstrating the asymmetric bypass of the `review_stacks_enabled` safety switch. [2](#0-1) [3](#0-2)

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
