### Title
`OpenedHandler#provision?` operator precedence bypasses `Repository#review_stacks_enabled` for `allow_with_label`/`prevent_with_label` behaviors - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` combines `review_stacks_enabled` with the provisioning-behavior checks using `&&`/`||` without parentheses, so Ruby's operator precedence binds `review_stacks_enabled` only to the `allow_all?` branch. The `allow_with_label?` and `prevent_with_label?` branches are evaluated independently of `review_stacks_enabled`, so a repository with review stacks explicitly disabled can still have a `ReviewStack` provisioned from an attacker-controlled fork PR.

### Finding Description
The intended binding is: `repository.review_stacks_enabled == true` must hold for **any** provisioning path to execute (config authorization gate). The actual code is: [1](#0-0) 

Ruby parses this as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. When `review_stacks_enabled: false` and `provisioning_behavior: :allow_with_label`, the first clause is `false`, but the second clause `(allow_with_label? && pull_request_has_provisioning_label?)` still evaluates independent of `review_stacks_enabled`, and is `true` when the attacker's PR carries the configured `provisioning_label_name`. `provision?` returns `true`, `respond_to_pull_request_opened?` returns `true`, and `process` calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!`.

`ReviewStackAdapter#create!` builds the stack directly from attacker-controlled payload fields, in particular `branch: params.pull_request.head.ref` [2](#0-1)  and enqueues it for provisioning via `Shipit::ReviewStackProvisioningQueue.add(stack)` [3](#0-2) . This is the attacker's own fork/branch, whose `shipit.yml` deploy steps are what execute on provisioning through `Command`/`PTY.spawn` in the task pipeline.

The webhook signature check (`verify_signature`) does not prevent this: the webhook is a genuine GitHub event for a real "opened" pull request against the tracked repository, signed correctly by GitHub, since the attacker only needs to open a PR (and, per the stated attacker capabilities, label it) — no forged signature is required. `drop_unhandled_event` also does not block it since `pull_request.opened` is a handled event.

### Impact Explanation
A repository owner who explicitly sets `review_stacks_enabled: false` reasonably expects no review stacks to ever be created for that repository. Due to this logic bug, if `provisioning_behavior` is `allow_with_label` (or `prevent_with_label`, inverted), an attacker opening a PR from their own fork with (or without) a specific label can force Shipit to create and provision a `ReviewStack` for a branch they fully control, leading to execution of attacker-supplied `shipit.yml` task steps via `Command`/`PTY.spawn` — Critical, matching "RCE on the deploy host via `Command`/`PTY.spawn`" and "a record written for a repository that did not authenticate it." This is repeatable against any tracked repository configured with `allow_with_label`/`prevent_with_label` and `review_stacks_enabled: false`.

### Likelihood Explanation
Requires: (1) a `Shipit::Repository` record exists for the target repo (tracked by Shipit), (2) `provisioning_behavior` is `allow_with_label` or `prevent_with_label`, (3) `review_stacks_enabled` is `false` (the exact scenario meant to be safe). Given these — a plausible, non-default-but-supported configuration — the attacker cost is trivial: open a PR from a fork with the required label state. No credentials, sessions, or tokens are needed.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates all three branches:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` (existing suite covers this area):
```ruby
test "#process does not provision when review_stacks_enabled is false, even with matching label" do
  repository = shipit_repositories(:shipit)
  repository.update!(review_stacks_enabled: false, provisioning_behavior: :allow_with_label, provisioning_label_name: "deploy-preview")
  payload = pull_request_payload(repository: repository, labels: [{ name: "deploy-preview" }])

  assert_no_difference -> { Shipit::Stack.count } do
    Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(payload).process
  end
end
```
With current code, this assertion fails: `Shipit::Stack.count` increases by 1 because `provision?` returns `true` despite `review_stacks_enabled == false`, confirming the binding `repository.review_stacks_enabled == true` is not actually enforced for the `allow_with_label`/`prevent_with_label` branches.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L87-94)
```ruby
          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```
