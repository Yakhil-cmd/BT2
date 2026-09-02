### Title
`OpenedHandler#provision?` operator precedence bug bypasses `review_stacks_enabled` gate for `prevent_with_label` repositories - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` uses `&&`/`||` in a way that only the `allow_all` branch is gated by `repository.review_stacks_enabled`; the `prevent_with_label` branch is not. An unprivileged GitHub user who opens a PR without the provisioning label against a repository configured with `review_stacks_enabled: false` and `provisioning_behavior: :prevent_with_label` can still trigger review-stack creation and provisioning.

### Finding Description
The binding the question asserts should hold is: `repository.review_stacks_enabled == true` must be true for every path that reaches `ReviewStackAdapter#create!`. Tracing `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:65-70`:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Because `&&` binds tighter than `||` in Ruby, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

Only the first disjunct is gated by `review_stacks_enabled`. The third disjunct — the `prevent_with_label` case — evaluates independently of `review_stacks_enabled`.

Evaluate both sides of the binding for `review_stacks_enabled == false`, `provisioning_behavior == :prevent_with_label`, PR has no provisioning label:
- Clause 1: `false && provisioning_behavior_allow_all?` → `false` (since behavior isn't `allow_all` anyway, and `review_stacks_enabled` is false).
- Clause 2: `provisioning_behavior_allow_with_label?` is `false` → `false`.
- Clause 3: `provisioning_behavior_prevent_with_label?` is `true`, `!pull_request_has_provisioning_label?` is `true` → `true`.

`provision?` returns `true`. `review_stacks_enabled` is `false`. The binding is broken: provisioning proceeds despite `review_stacks_enabled == false`.

`process` then calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` at `opened_handler.rb:44-46` [2](#0-1) . `Repository#review_stacks` is an unconditional `has_many` association, not filtered by `review_stacks_enabled` [3](#0-2) , so the scope is available regardless of the flag. `ReviewStackAdapter#create!` then builds `stack_attributes` with `branch: params.pull_request.head.ref` (attacker-controlled PR head ref) and calls `scope.create!(stack_attributes)`, followed by `Shipit::ReviewStackProvisioningQueue.add(stack)` [4](#0-3) , queuing the stack for provisioning, which eventually leads to task execution against the attacker's branch/`shipit.yml`.

No existing guard catches this: `params` schema validation only checks payload shape, not the semantic AND/OR logic; `Repository` validations (owner/name format) don't touch `review_stacks_enabled`; there is no additional check anywhere else in `process` or `find_or_create!` re-verifying `review_stacks_enabled` before creating a review stack.

Note: this path assumes the webhook itself is legitimately delivered by GitHub for a real PR (the repository owner must have connected the repo to Shipit and misconfigured `provisioning_behavior: :prevent_with_label` while leaving `review_stacks_enabled: false`), so it does not require forging a webhook signature — it only requires the attacker to open an ordinary PR without the provisioning label.

### Impact Explanation
For any repository connected to this Shipit instance with `provisioning_behavior: :prevent_with_label` and `review_stacks_enabled: false` (a config combination intended to disable review-stack automation entirely), an external, unprivileged contributor can still cause a `Shipit::Stack`/`ReviewStack` row to be created for their PR and queued for provisioning purely by opening a PR without a specific label. Provisioning subsequently drives task execution (via `ReviewStackProvisioningQueue` → provisioning handlers → `TaskCommands`/`Command`/`PTY.spawn`) against attacker-controlled branch content, which is a Critical-severity RCE-on-deploy-host path per the stated impact categories. This is repeatable against every repository configured this way, and each PR opened without the label creates/re-triggers a new stack.

### Likelihood Explanation
Preconditions: the target repository must have `provisioning_behavior` set to `prevent_with_label` and `review_stacks_enabled` set to `false` — a plausible, even encouraged, configuration for maintainers who want the "block provisioning unless labeled" semantics while believing the disabled flag is an additional safety switch. Attacker cost is trivial: open a normal PR without adding the label, which any external contributor with fork-PR access can do. No secrets, tokens, or privileged roles needed. Fully repeatable per PR/per repository matching this configuration.

### Recommendation
Fix operator precedence/grouping in `provision?` so `review_stacks_enabled` gates all three behavior branches, e.g.:
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
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` style (existing helper `configure_provisioning_behavior` at line 189):
```ruby
test "does not create stacks for prevent_with_label repos when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,        # review_stacks_enabled = false
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []   # no provisioning label

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Binding assertion: `repository.review_stacks_enabled` (`false`) must equal the precondition for `Shipit::Stack.count` to remain unchanged; current code causes `assert_no_difference` to fail because a stack is created with `branch == payload["pull_request"]["head"]["ref"]`, demonstrating the divergence.

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

**File:** app/models/shipit/repository.rb (L47-48)
```ruby
    has_many :stacks, dependent: :destroy
    has_many :review_stacks, dependent: :destroy
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
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
```
