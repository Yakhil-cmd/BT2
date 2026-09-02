### Title
`ReopenedHandler#unarchive?` operator-precedence bug allows PR reopen to bypass `review_stacks_enabled` - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler#unarchive?` uses the same boolean expression as `OpenedHandler#provision?`, and Ruby's `&&`/`||` precedence causes `review_stacks_enabled` to gate only the `allow_all` branch, not the `allow_with_label`/`prevent_with_label` branches. When a repository has `review_stacks_enabled: false` but `provisioning_behavior` set to `allow_with_label` or `prevent_with_label`, a `reopened` webhook for a PR matching the label condition will still call `ReviewStackAdapter#unarchive!`/`create!`, provisioning a stack the master switch was meant to disable.

### Finding Description
The claimed broken binding is: `review_stacks_enabled == true` should be required for every branch of `unarchive?`, but in code it is only required for the `allow_all` branch:

```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Because `&&` binds tighter than `||` in Ruby, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && label_present?) || (prevent_with_label? && !label_present?)`. The `review_stacks_enabled` flag is not applied to the second and third disjuncts at all. This is the identical defect present in `OpenedHandler#provision?` [2](#0-1) , `LabeledHandler#archive?`/`#unarchive?`, and `UnlabeledHandler#archive?`/`#unarchive?`, all of which share the same pattern.

`process` calls `stack.unarchive!` when `respond_to_pull_request_reopened?` (i.e. `action == "reopened" && unarchive?`) is true [3](#0-2) . `stack` is a `ReviewStackAdapter` scoped to `repository.review_stacks` [4](#0-3) . `ReviewStackAdapter#unarchive!` either unarchives an existing archived stack and enqueues it for provisioning, or creates a brand-new `ReviewStack` (via `create!`) and enqueues it, if no stack exists for that PR's environment [5](#0-4) , [6](#0-5) .

Exploit flow: repository has `review_stacks_enabled: false`, `provisioning_behavior: allow_with_label`, `provisioning_label_name: "deploy-preview"`. Attacker opens a PR from a fork; since `provisioning_behavior` isn't `allow_all`, `OpenedHandler#provision?` also has its label branch active independent of `review_stacks_enabled`, so a stack could already be created on open too - but per the scenario, assume the PR is opened while `provisioning_behavior` is `allow_all` (blocked correctly since `review_stacks_enabled` is false and only the `allow_all` branch is properly gated). Attacker adds their label and gets the PR closed. Later, while `review_stacks_enabled` remains `false`, the repository's `provisioning_behavior` is switched to `allow_with_label` (an operator action, not attacker-controlled). Attacker reopens the PR. `unarchive?` evaluates `provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?` as `true`, entirely bypassing the disabled `review_stacks_enabled` flag, and `ReviewStackAdapter#unarchive!`/`create!` runs, creating/reactivating a stack and enqueuing it into `Shipit::ReviewStackProvisioningQueue` [7](#0-6) .

None of the existing guards prevent this: there's no signature/webhook-authenticity issue here (the webhook itself is legitimate GitHub traffic for a real PR event), `respond_to_pull_request_reopened?` only checks `action == "reopened"` and the flawed `unarchive?`, and no model validation enforces `review_stacks_enabled` at the `ReviewStack` or `Repository` level.

### Impact Explanation
The impact is that a repository administrator's explicit choice to disable dynamic review-stack provisioning (`review_stacks_enabled: false`) is silently overridden whenever `provisioning_behavior` is `allow_with_label` or `prevent_with_label`, letting an attacker-controlled PR (via label + reopen) cause a `Shipit::ReviewStack` record to be created and queued for provisioning (`ReviewStackProvisioningQueue.add`) [8](#0-7) . Actual downstream execution (`TaskCommands#perform`/`Command`/`PTY.spawn`) depends on the later cron-driven `ReviewStackProvisioningQueue.work` and the host application's `ProvisioningHandler#up` implementation [9](#0-8) , which is outside this engine's control - so whether this reaches an actual `Command`/`PTY.spawn` RCE depends on the host's provisioning handler. Within this engine's own code, the demonstrable impact is: bypassing the `review_stacks_enabled` authorization gate to create/reactivate a stack and place it into the active provisioning workflow for a repository that opted out, which is a real authorization-bypass bug but its severity as "Critical RCE" is contingent on host-app provisioning handler behavior not present in this repo.

### Likelihood Explanation
Exploitation requires the specific repository configuration `review_stacks_enabled: false` combined with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` at the moment the `reopened` webhook is processed - this is a real, reachable configuration state (not necessarily requiring "momentary toggling"; an operator could simply pre-configure `provisioning_behavior` before flipping on `review_stacks_enabled`, or disable review stacks while leaving `provisioning_behavior` unchanged). Given that configuration, the rest of the exploit is fully within the described attacker capabilities (label their own PR, close/reopen it). The existing test suite (`reopened_handler_test.rb`) never exercises `review_stacks_enabled: false` combined with the label-based behaviors, so this divergence is untested.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates every branch, e.g.:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the identical fix to `OpenedHandler#provision?`, `LabeledHandler#archive?`/`#unarchive?`, and `UnlabeledHandler#archive?`/`#unarchive?`, which share the same defective pattern.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`, add:
```ruby
test "does not unarchive/create stacks when review_stacks_enabled is false, even with allow_with_label + matching label" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.not_archived.count } do
    Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process
  end

  assert stack.reload.archived?, "Expected stack to remain archived since review_stacks_enabled is false"
end
```
Running this against current code fails: `unarchive?` returns `true` despite `review_stacks_enabled == false`, and the stack is unarchived/queued for provisioning - demonstrating the equality `review_stacks_enabled(false) == effective_gate(true)` is broken for the label branches.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L55-59)
```ruby
          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L9-11)
```ruby
    def self.add(stack)
      stack.enqueue_for_provisioning
    end
```

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L29-37)
```ruby
    def provision(stack)
      if stack.provisioner.provision?
        stack.provision
      else
        Rails.logger.info(
          "Putting review ReviewStack<#{stack.id}> back into the provisioning queue - #provision? was falsey."
        )
      end
    end
```
