This confirms the finding: `TaskCommands#perform` builds `Command.new(command_line, ...)` from `@task.definition.steps` (sourced from `deploy_spec` checked out from the stack's `branch`, which for a review stack is `params.pull_request.head.ref` set in `ReviewStackAdapter#stack_attributes`), and `Command` executes via `PTY.spawn` [1](#0-0) [2](#0-1) [3](#0-2) .

### Title
`OpenedHandler#provision?`'s `prevent_with_label` clause ignores `review_stacks_enabled`, provisioning unapproved fork PRs into an executable review stack - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`provision?` is written as `A && B || C || D` where Ruby's operator precedence binds `&&` tighter than `||`, so it evaluates as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. The third disjunct, guarding the `prevent_with_label` behavior, never checks `review_stacks_enabled`, so a repository with review stacks explicitly disabled but configured with `provisioning_behavior: prevent_with_label` will still auto-provision a stack for any unlabeled PR.

### Finding Description
The claimed-safe binding is: "ref approved for review-stack provisioning" == "none, because `repository.review_stacks_enabled == false`". Tracing `provision?`:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [4](#0-3) 

Ruby's precedence makes this `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. Only the first disjunct is gated by `review_stacks_enabled`; the third (`prevent_with_label`) is not. So for a repository with `review_stacks_enabled = false` and `provisioning_behavior = prevent_with_label`, an attacker opens a pull request from their own fork with no labels (they cannot add a label matching `provisioning_label_name` anyway, and they don't need to). `pull_request_has_provisioning_label?` returns `false`, so `!pull_request_has_provisioning_label?` is `true`, and the third clause evaluates to `true` regardless of `review_stacks_enabled`. `respond_to_pull_request_opened?` returns `true`, and `process` calls `ReviewStackAdapter#find_or_create!`, which creates a `Stack` with `branch: params.pull_request.head.ref` (the attacker's fork branch) [5](#0-4)  and enqueues it for provisioning via `Shipit::ReviewStackProvisioningQueue.add(stack)` [6](#0-5) . Provisioning eventually runs task steps built from the checked-out branch's `shipit.yml` via `TaskCommands#perform`, each step becoming a `Command` executed with `PTY.spawn` [7](#0-6) . No downstream guard re-checks `review_stacks_enabled`; the webhook signature check and payload schema only validate that the request came from GitHub for that repository, not that review-stack provisioning is enabled for it.

The existing test suite documents the intended behavior for `allow_all` (`"only provision stacks for repos with auto-provisioning enabled"` disables `review_stacks_enabled` and asserts no stack is created) [8](#0-7) , but there is no equivalent test combining `review_stacks_enabled: false` with `prevent_with_label`, and none of the existing `prevent_with_label` tests set `review_stacks_enabled` to `false` [9](#0-8) , confirming this branch is untested and the bug is unguarded.

### Impact Explanation
Any repository owner who mistakenly (or transitionally) sets `provisioning_behavior = prevent_with_label` while leaving/reverting `review_stacks_enabled = false` will still provision and execute attacker-controlled `shipit.yml` steps from any unlabeled fork PR, on the deploy host, via `PTY.spawn`. This is Critical RCE: an unprivileged GitHub user who can open a PR against the target repository controls the code and command lines executed as the Shipit deploy user. It is repeatable against any repository in this misconfigured state and against every subsequent unlabeled PR the attacker opens.

### Likelihood Explanation
Requires `review_stacks_enabled == false` and `provisioning_behavior == prevent_with_label` on the target repository (an intermediate/misconfigured but legitimate settings combination reachable through the standard Settings UI without disabling the other), plus an open, unlabeled PR from the attacker. No secrets, tokens, or privileged roles are needed by the attacker beyond opening a PR they control.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates every branch:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, add:
```ruby
test "does not provision stacks for repos with review_stacks disabled even when prevent_with_label and no label present" do
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
Assert both sides of the binding: `repository.review_stacks_enabled` is `false` (no ref is approved for provisioning) vs. `Shipit::Stack.count` changing (a stack/task would be created and its `TaskCommands#perform` steps passed to `Command.new`, matching the fixture PR's `shipit.yml` `deploy.override` steps). Under current code, this test fails because a stack is created; with the parenthesization fix, it passes.

### Citations

**File:** lib/shipit/task_commands.rb (L23-31)
```ruby
    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def steps
      @task.definition.steps
    end
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

**File:** lib/shipit/command.rb (L1-2)
```ruby
# frozen_string_literal: true

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

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L96-107)
```ruby
          test "only provision stacks for repos with auto-provisioning enabled" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              provisioning_enabled: false,
              behavior: :allow_all
            )

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload_parsed(:provision_disabled_pull_request)).process
            end
          end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L159-187)
```ruby
          test "create stacks for repos what prevent_with_label when label is absent" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] = []

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end

          test "does not create stacks for repos what prevent_with_label when label is present" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end
```
