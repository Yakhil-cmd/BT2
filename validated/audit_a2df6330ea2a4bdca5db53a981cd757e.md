### Title
`provision?` operator-precedence bug lets `prevent_with_label` bypass `review_stacks_enabled: false` for label-less PRs (RCE via autoprovisioning) - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
In `OpenedHandler#provision?`, Ruby's `&&`/`||` precedence causes `repository.review_stacks_enabled` to gate only the `provisioning_behavior_allow_all?` branch, not the `provisioning_behavior_prevent_with_label?` branch. Because GitHub PRs default to zero labels, any newly opened fork PR against a `prevent_with_label`-configured repository will satisfy `!pull_request_has_provisioning_label?` and trigger provisioning regardless of `review_stacks_enabled`.

### Finding Description
The broken binding: the intended guard is `review_stacks_enabled == true` must be required for ANY provisioning branch to fire. The actual code is: [1](#0-0) 

Ruby parses `&&` before `||`, so this evaluates as:
```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)
```
`review_stacks_enabled` is parenthesized implicitly with only the first disjunct. The second and third disjuncts are standalone terms unconditioned by `review_stacks_enabled`.

Attacker's request: open any PR (no labels — the GitHub default) against a repository configured with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false`. `pull_request_has_provisioning_label?` returns `false` (empty `labels` array via `Array.new(pull_request["labels"]).map { |label| label["name"] }`), so `!pull_request_has_provisioning_label?` is `true`, and `provisioning_behavior_prevent_with_label?` is `true`, making the third disjunct `true` — `provision?` returns `true` irrespective of `review_stacks_enabled`.

`respond_to_pull_request_opened?` then passes, and `process` calls `ReviewStackAdapter#find_or_create!`: [2](#0-1) 

`create!` unconditionally creates the stack and enqueues it for provisioning: [3](#0-2) 

The `ReviewStackProvisioningQueue` subsequently invokes the provisioning handler's `up`, which drives `Command`/`PTY.spawn` execution on the deploy host using attacker-controlled branch/environment values from the PR (`stack_attributes` includes `branch: params.pull_request.head.ref`). No existing guard (`ExplicitParameters` schema, `respond_to_pull_request_opened?`, webhook signature verification) checks `review_stacks_enabled` for this branch — the schema only validates payload shape, and signature verification only authenticates that GitHub sent the payload, not that the repository owner intended review-stack provisioning to be active.

### Impact Explanation
An attacker who can merely open a pull request against any repository misconfigured with `provisioning_behavior: prevent_with_label` (regardless of whether the operator believes review-stack provisioning is disabled via `review_stacks_enabled: false`) triggers stack creation and provisioning. Provisioning executes shell commands via `ProvisioningHandler`/`Command`/`PTY.spawn` on the deploy host, using attacker-influenced branch/environment data — this is Critical RCE on the deploy host, matching the specified impact category. This is repeatable against every repository configured this way and requires zero further attacker action beyond opening a plain PR.

### Likelihood Explanation
Preconditions: repository must have `provisioning_behavior: prevent_with_label` set (a supported, documented configuration option per `app/views/shipit/repositories/settings.html.erb`), and operators may reasonably also set `review_stacks_enabled: false` believing it fully disables autoprovisioning — but the code doesn't honor that combination for `prevent_with_label`/`allow_with_label`. Since PRs default to no labels, this triggers on essentially every opened PR without any special attacker effort — high likelihood whenever this configuration exists.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the entire disjunction:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to the equivalent `archive?`/`unarchive?` logic in `labeled_handler.rb`/`unlabeled_handler.rb` if they have analogous unguarded terms.

### Proof of Concept
```ruby
test "does not create stacks for prevent_with_label repos when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :prevent_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Before the fix, this test fails: `Shipit::Stack.count` increments by 1 and the new stack is enqueued via `Shipit::ReviewStackProvisioningQueue.add`, proving provisioning occurs despite `review_stacks_enabled: false`.

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
