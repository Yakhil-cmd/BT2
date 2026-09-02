### Title
`ReviewStackAdapter#find_or_create!`/`#unarchive!` provisions review stacks even when `review_stacks_enabled` is false due to `&&`/`||` operator‑precedence bug shared by `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler` does not define a method literally named `provision?`; the gating method is `unarchive?`, but it is textually identical to `OpenedHandler#provision?` and shares the same logic bug. Because `&&` binds tighter than `||` in Ruby, `repository.review_stacks_enabled` only gates the `allow_all` branch of the expression, not the `allow_with_label`/`prevent_with_label` branches, so a repository configured with `review_stacks_enabled = false` and `provisioning_behavior = allow_with_label` will still unarchive/provision a review stack whenever the PR carries the configured label.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == effective_gate_for_all_provisioning_behaviors`. The actual code in both handlers is: [1](#0-0) 

```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Due to Ruby operator precedence (`&&` before `||`), this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

`review_stacks_enabled` is only ANDed into the first disjunct. If `review_stacks_enabled == false` but `provisioning_behavior == allow_with_label` and the PR carries the configured label, the second disjunct alone evaluates true, so `unarchive?` returns true regardless of the disabled flag.

Path: a reopened-PR webhook reaches `ReopenedHandler#process`, which calls `respond_to_pull_request_reopened?` → `unarchive?` [2](#0-1) , and if true, calls `stack.unarchive!` on a `ReviewStackAdapter`, which either unarchives an archived stack or, if none exists, calls `create!` to provision a brand-new `ReviewStack` and enqueue it via `Shipit::ReviewStackProvisioningQueue.add` [3](#0-2) , [4](#0-3) .

Same bug independently exists in `OpenedHandler#provision?` [5](#0-4) , which calls `ReviewStackAdapter#find_or_create!` directly on `opened`.

None of the existing guards intercept this: `verify_signature`/`drop_unhandled_event`/`ExplicitParameters` validate payload shape and authenticity of the webhook sender (GitHub), not the business logic of `review_stacks_enabled`; `Repository` validations only constrain `owner`/`name` format, not `provisioning_behavior` combinations. The existing test suite (`test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`) never exercises `review_stacks_enabled: false` together with `allow_with_label`/`prevent_with_label`, so this divergence is untested.

Note on question accuracy: the question refers to "`ReopenedHandler#provision?`" but the actual method in this file is `unarchive?`; there is no `provision?` method defined in `ReopenedHandler`. The underlying logic bug it describes is nonetheless real and present verbatim in this file's `unarchive?` method (and in `OpenedHandler#provision?`).

### Impact Explanation
When exploited, a repository configured by its Shipit operator with `review_stacks_enabled = false` (intending to disable all PR-driven review-stack provisioning) will still have review stacks created/unarchived and queued for provisioning whenever `provisioning_behavior` is `allow_with_label` (label present) or `prevent_with_label` (label absent). Provisioning enqueues the stack for the deploy/provision pipeline, which runs commands as part of stack setup — this is an unauthorized deploy/provisioning action against the operator's explicit configuration. The blast radius is limited to the specific repository whose Shipit `Repository` record carries this exact misconfigured combination; it does not cross into other repositories/stacks, and does not directly leak secrets or forge webhook signatures.

### Likelihood Explanation
Requires: (1) the target repository already tracked in Shipit, (2) an operator having explicitly set `review_stacks_enabled = false` while leaving `provisioning_behavior` at `allow_with_label` or `prevent_with_label` (a plausible but non-default combination), and (3) the attacker being able to label their own PR and close/reopen it or open a new PR — all within the stated attacker capability. Given that configuration exists, the attack is trivial and fully repeatable (label add/remove and PR open/reopen/close cycles) with no privileged Shipit access needed.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates every branch:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the identical fix to `OpenedHandler#provision?`.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`, add:
```ruby
test "does NOT unarchive/provision when review_stacks_enabled is false, even with allow_with_label and label present" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :allow_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process

  assert stack.reload.archived?, "Expected stack to remain archived because review_stacks_enabled is false"
end
```
Assert `repository.review_stacks_enabled == false` (left side of the binding) versus `stack.reload.archived? == false` (right side, i.e., effective gate) — with the current code, the stack becomes unarchived/provisioned despite `review_stacks_enabled` being false, proving the divergence; the assertion above will fail against current code and pass once the parenthesization fix is applied.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
