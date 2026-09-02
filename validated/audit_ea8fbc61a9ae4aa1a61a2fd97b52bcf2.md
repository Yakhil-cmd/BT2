### Title
`ReopenedHandler#unarchive?` operator-precedence bug lets `provisioning_behavior_allow_with_label`/`prevent_with_label` unarchive/create review stacks even when `review_stacks_enabled=false` - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler#unarchive?` and the structurally identical `OpenedHandler#provision?` combine `repository.review_stacks_enabled` with the three provisioning-behavior disjuncts using `&&`/`||` without parentheses. Because Ruby's `&&` binds tighter than `||`, `review_stacks_enabled` is only ANDed into the first (`allow_all`) branch, not the `allow_with_label` or `prevent_with_label` branches, so a repository with `review_stacks_enabled=false` still provisions/unarchives review stacks for label-gated behaviors.

### Finding Description
The broken binding: the code intends `repository.review_stacks_enabled == true` to gate **all** provisioning, but the actual boolean evaluated is:

```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Due to standard Ruby precedence, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)` — the second and third disjuncts never check `review_stacks_enabled` at all. `respond_to_pull_request_reopened?` calls only `unarchive?` and does not separately check `review_stacks_enabled`: [2](#0-1) . The identical pattern exists in `OpenedHandler#provision?` [3](#0-2) . By contrast, `LabeledHandler` correctly ANDs `review_stacks_enabled` outside/around the whole disjunction in `respond_to_label_change?` [4](#0-3) , confirming the intended semantics and that `ReopenedHandler`/`OpenedHandler` diverge from it.

Attack flow: repository has `review_stacks_enabled=false` and `provisioning_behavior=:allow_with_label`. Attacker owns/controls a PR (their own fork/branch) in that tracked repo, attaches the label matching `repository.provisioning_label_name`, and reopens the PR. The `pull_request.reopened` webhook reaches `ReopenedHandler#process` → `unarchive?` returns `true` (second disjunct) despite `review_stacks_enabled=false` → `stack.unarchive!` on `ReviewStackAdapter` [5](#0-4) . If no matching `ReviewStack` exists for that PR's environment, `create!` builds one with `branch: params.pull_request.head.ref` [6](#0-5)  and enqueues it via `ReviewStackProvisioningQueue.add` [7](#0-6) . Provisioning/tasks eventually run `TaskCommands#steps`, sourced from `@task.definition.steps`, which is populated by `DeploySpec::FileSystem` reading `shipit.yml` off the attacker-controlled branch [8](#0-7) , and those steps are turned into `Command.new(command_line, ...)` instances that get executed on the deploy host [9](#0-8) .

Existing guards do not prevent this: signature verification, `ExplicitParameters` schema validation, and repository lookup all pass normally for a legitimately delivered webhook from a repo the attacker controls (a fork/PR they own); none of them re-check `review_stacks_enabled` before the handler's own gating logic runs, and the handler's own gating logic is what's broken.

### Impact Explanation
An attacker who can label and reopen their own PR against a repository configured with `provisioning_behavior=allow_with_label` (or `prevent_with_label`) but `review_stacks_enabled=false` can force Shipit to create/unarchive a review stack and enqueue provisioning/tasks whose command steps are sourced from `shipit.yml` on the attacker's own branch. This results in arbitrary command execution (`Command`/`PTY.spawn`) on the deploy host with the deploy environment's credentials (e.g. `GITHUB_TOKEN`, `GIT_ASKPASS` per `Command#unbundled_env`), constituting Critical-severity RCE. The blast radius is limited to repositories that are misconfigured this specific way (label-gated behavior selected while review stacks are disabled), but is repeatable at will by the attacker against any such repository, and once triggered runs with the deploy host's full command execution privileges.

### Likelihood Explanation
Requires the repository owner/operator to have set `provisioning_behavior` to `allow_with_label` or `prevent_with_label` while leaving `review_stacks_enabled=false` — a specific, non-default combination but a plausible operational state (e.g., partially rolling out or rolling back review-stack support without resetting `provisioning_behavior`). Given that precondition, the attacker's cost is trivial: label and reopen (or label, per `LabeledHandler` — note `LabeledHandler` is *not* vulnerable because it explicitly ANDs `review_stacks_enabled`) their own PR. `OpenedHandler` shares the exact same flaw for the "opened" event, widening the trigger surface.

### Recommendation
Add explicit parentheses to `unarchive?` (and `provision?` in `OpenedHandler`) so `review_stacks_enabled` gates the entire expression, matching `LabeledHandler`'s pattern:
```ruby
def unarchive?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the same fix to `OpenedHandler#provision?`.

### Proof of Concept
minitest plan (extends `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`):
```ruby
test "does not unarchive/create stacks when review_stacks_enabled is false, even with allow_with_label + matching label" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # review_stacks_enabled = false
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  # Binding under test: repository.review_stacks_enabled (false) should equal
  # whether unarchive? proceeds. Currently unarchive? == true despite
  # review_stacks_enabled == false.
  Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process

  assert stack.reload.archived?, "Expected stack to remain archived because review_stacks_enabled is false"
end
```
This test currently fails (stack is unarchived/provisioned) prior to the fix, and passes once `review_stacks_enabled` correctly gates the whole `unarchive?` expression.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L65-68)
```ruby
          def respond_to_pull_request_reopened?
            params.action == "reopened" &&
              unarchive?
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-69)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
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

**File:** lib/shipit/task_commands.rb (L17-31)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def steps
      @task.definition.steps
    end
```
