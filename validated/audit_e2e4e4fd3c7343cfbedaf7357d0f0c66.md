### Title
`OpenedHandler#provision?` operator-precedence bug bypasses `review_stacks_enabled` for `allow_with_label`/`prevent_with_label` repositories - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`provision?` intends `review_stacks_enabled` to gate all provisioning behaviors, but Ruby's `&&`/`||` precedence only applies it to the `allow_all` branch. A repository configured with `provisioning_behavior_allow_with_label` and `review_stacks_enabled: false` will still auto-create a review stack (and enqueue provisioning/deploy commands) whenever a pull request carries the configured label, which an attacker can self-apply if they have any label-adding ability on their own PR.

### Finding Description
The broken binding is:
`repository.review_stacks_enabled == false` should imply `provision? == false` for **every** provisioning behavior, but the actual code is: [1](#0-0) 

Due to Ruby operator precedence, `&&` binds tighter than `||`, so this parses as:

```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)
```

`review_stacks_enabled` is only ANDed into the first disjunct. For a repository with `provisioning_behavior_allow_with_label? == true` and `review_stacks_enabled == false`, `provision?` still evaluates the second disjunct `(allow_with_label? && pull_request_has_provisioning_label?)`, which is `true` if the attacker's PR carries the configured label, independent of `review_stacks_enabled`. Same applies to `prevent_with_label` (the third disjunct entirely ignores `review_stacks_enabled`).

Call path: `OpenedHandler#process` → `respond_to_pull_request_opened?` → `provision?` (true) → `ReviewStackAdapter#find_or_create!` → `create!`, which persists a new `ReviewStack` with `branch: params.pull_request.head.ref` and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)`: [2](#0-1) 

The provisioning worker later calls `stack.provisioner.provision?`/`stack.provision`, which triggers task execution (`Command#start` → `PTY.spawn`) exactly as it would for any legitimately provisioned review stack: [3](#0-2) 

Existing test coverage (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`) only exercises `review_stacks_enabled: false` in combination with `provisioning_behavior_allow_all` (which correctly blocks creation), and exercises `allow_with_label`/`prevent_with_label` only with the default `review_stacks_enabled: true`. No test combines `review_stacks_enabled: false` with `allow_with_label`, so the gap was never caught. None of the standard guards (`ExplicitParameters` schema, `drop_unhandled_event`, webhook signature verification, `Repository` validations) constrain this logic path — they validate payload shape/authenticity of the webhook itself, not the intended business-level authorization semantics of `review_stacks_enabled`.

### Impact Explanation
An attacker who can add the configured provisioning label to their own pull request (self-label, triage role, or any contributor with label permissions on a repo using GitHub's collaborator/triage roles) on a repository whose operator explicitly disabled review stacks (`review_stacks_enabled: false`) can force Shipit to create a `ReviewStack` and drive it through the provisioning pipeline, which ultimately executes commands via `Command#start`/`PTY.spawn` on the deploy host using the branch/environment the attacker controls. This is an unauthorized deploy/stack-creation bypassing an operator-set safety control, repeatable per pull request/label toggle against any repository configured this way. This matches the Critical category: "an unauthorized deploy... via `Command`/`PTY.spawn`" and "a record written for a repository that did not authenticate it."

### Likelihood Explanation
Preconditions: target repository has `provisioning_behavior: allow_with_label` (or `prevent_with_label`) and `review_stacks_enabled: false`; the attacker needs only the ability to add the pre-existing label to a PR (or, for `prevent_with_label`, simply to open a PR without the label) — no Shipit credentials, no maintainer role, no webhook secret required, since this is a normal GitHub `pull_request.opened` webhook the repository is already configured to send. Cost is low and the behavior is deterministic and repeatable for every PR opened against that repository.

### Recommendation
Fix operator grouping in `provision?` so `review_stacks_enabled` gates all three behaviors, e.g.:

```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` add:

```ruby
test "does not create stacks for allow_with_label repos when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::ReviewStack.count } do
    OpenedHandler.new(payload).process
  end
end
```

Before the fix, `Shipit::ReviewStack.count` increments (assertion fails), demonstrating `provision?` returns `true` despite `repository.review_stacks_enabled == false`. After applying the recommended fix, the count does not change, matching the intended equality `review_stacks_enabled == false ⇒ provision? == false`.

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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L17-37)
```ruby
    def work
      queued_stacks.find_each(&method(:provision))
    end

    def queued_stacks
      @queued_stacks ||= Shipit::ReviewStack
                         .with_provision_status(:deprovisioned)
                         .where(awaiting_provision: true)
    end

    private

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
