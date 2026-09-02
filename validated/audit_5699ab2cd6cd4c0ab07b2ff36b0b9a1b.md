### Title
`provision?` operator-precedence flaw lets `prevent_with_label` (and `allow_with_label`) bypass `review_stacks_enabled` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` combines `repository.review_stacks_enabled` with the three provisioning-behavior checks using `&&`/`||` without parentheses. Because `&&` binds tighter than `||`, `review_stacks_enabled` only gates the `allow_all` clause; it does nothing for the `allow_with_label` and `prevent_with_label` clauses. A repository with `review_stacks_enabled == false` and `provisioning_behavior == 'prevent_with_label'` will still auto-create a `ReviewStack` for any PR opened without the provisioning label.

### Finding Description
The intended binding is: `ReviewStack created ⇔ repository.review_stacks_enabled == true AND (one of the behavior conditions holds)`. The actual code is: [1](#0-0) 

Due to Ruby precedence this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)`

so `review_stacks_enabled` is entirely absent from the second and third disjuncts. `respond_to_pull_request_opened?` calls `provision?` directly [2](#0-1) , and `process` unconditionally calls `ReviewStackAdapter#find_or_create!` when it returns true [3](#0-2) . `find_or_create!`/`create!` in `ReviewStackAdapter` performs no check of `review_stacks_enabled` itself — it just creates the stack, its `PullRequest`, and enqueues provisioning [4](#0-3) .

Attack: given a repository configured with `review_stacks_enabled = false` and `provisioning_behavior = 'prevent_with_label'`, an unprivileged attacker who can open a PR against that repository (or trigger the equivalent `pull_request.opened` webhook payload naming that `repository.full_name`) simply opens a PR **without** adding the provisioning label. `prevent_with_label? && !has_label` is true, so `provision?` returns true irrespective of `review_stacks_enabled`, and a `ReviewStack` + queued provisioning job is created for a repository that explicitly opted out of review-stack auto-provisioning.

No existing guard catches this: `respond_to_pull_request_opened?` only checks `action == "opened"`; there is no separate `review_stacks_enabled` check anywhere else in the handler or adapter; webhook signature verification only authenticates that the payload came from GitHub for the named repository, it does not enforce the operator's `review_stacks_enabled` business rule.

### Impact Explanation
For any repository where an operator has intentionally set `review_stacks_enabled = false` but left a `provisioning_behavior` other than `allow_all` configured (e.g., `prevent_with_label`), an attacker who can open PRs against that repo can force creation of a `ReviewStack`, its `PullRequest` record, and enqueue it for provisioning — running whatever provisioning steps/CI config the stack executes. This is a repository-state mutation that the operator explicitly disabled, matching the "Critical - cross-repository/record written for a repository that did not authenticate it" category, since the resulting stack executes attacker-controlled branch content during provisioning.

### Likelihood Explanation
Preconditions are configuration-only and plausible: `review_stacks_enabled == false` plus `provisioning_behavior == 'prevent_with_label'` (or `'allow_with_label'`, which is also affected by the same missing parenthesization, though the label-presence bit runs the other way). No secrets, tokens, or privileged roles are needed — just the ability to open a PR (or send a matching `pull_request.opened` webhook naming the target `repository.full_name`) with or without a label, which is trivially repeatable against any repository in this misconfigured state.

### Recommendation
Fix operator precedence by requiring `review_stacks_enabled` for every branch:
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
Apply the same fix to the identical pattern in `ReopenedHandler#unarchive?` [5](#0-4) .

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does not create stacks when review_stacks_enabled is false, even for prevent_with_label without a label" do
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
Binding under test: `repository.review_stacks_enabled == false` must imply `Shipit::Stack.count` unchanged after `process`. With the current code, `provision?` evaluates `(false && allow_all?) || (allow_with_label? && has_label) || (true && true)` → `true`, and the assertion fails, demonstrating the bug.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-85)
```ruby
          def find_or_create!
            stack || create!
          end

          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

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

          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
          end

          private

          attr_reader :params, :scope

          def action
            params.action
          end

          def repo_name
            params.repository["full_name"]
          end

          def pr_number
            params.number
          end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
