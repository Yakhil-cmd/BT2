### Title
Review-stack auto-provisioning bypasses `review_stacks_enabled` for `prevent_with_label` (and `allow_with_label`) repositories - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` uses `&&`/`||` without parentheses so that `repository.review_stacks_enabled` only scopes the `provisioning_behavior_allow_all?` branch, not the `provisioning_behavior_allow_with_label?` or `provisioning_behavior_prevent_with_label?` branches. Consequently, a repository with `review_stacks_enabled: false` and `provisioning_behavior: prevent_with_label` will still auto-create and queue-for-provisioning a `Shipit::ReviewStack` from an unlabeled, unapproved pull request.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == true` must hold for any PR-triggered `ReviewStack` provisioning to occur (i.e., review stacks are an explicit opt-in feature gated by this single flag). The actual code in `provision?` is: [1](#0-0) 

Due to Ruby operator precedence (`&&` binds tighter than `||`), this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

So for `prevent_with_label` repositories, `review_stacks_enabled` is never evaluated at all. If an operator sets `review_stacks_enabled: false` (intending to disable dynamic review stacks) but leaves `provisioning_behavior: prevent_with_label` configured (label name set), any unlabeled PR opened by an unprivileged GitHub user still satisfies `provision?`, and `process` calls `ReviewStackAdapter#find_or_create!` [2](#0-1) , which creates a `ReviewStack` with `branch: params.pull_request.head.ref` [3](#0-2)  and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)`.

The cron task `cron:minutely` regularly calls `Shipit::ReviewStackProvisioningQueue.work`, which for any queued, deprovisioned stack calls `stack.provisioner.provision?` and then `stack.provision` [4](#0-3) , transitioning `provision_status` to `provisioning` and invoking `stack.provisioner.up` [5](#0-4) , which (per the default/host-configured provisioning handler and subsequent deploy tasks) reads `shipit.yml`/commands from the stack's `branch` — the attacker's `head.ref` — for command execution. No approval gate (`review_stacks_enabled`) was ever satisfied for this path, so the binding is broken: a stack gets created and queued for provisioning even though the repository's review-stacks feature is disabled.

Existing guards do not catch this: there is no signature/webhook check bypassed here (this is a logic bug independent of webhook auth), `respond_to_pull_request_opened?` only checks `params.action == "opened" && provision?` [6](#0-5) , and none of the `ExplicitParameters` schema, model validations, or `EnvironmentVariables#permit` mechanisms enforce `review_stacks_enabled` — that enforcement is only supposed to happen inside `provision?`, where it is broken by operator precedence.

### Impact Explanation
For any repository misconfigured with `review_stacks_enabled: false` plus `provisioning_behavior: prevent_with_label`, an unprivileged PR author (no label needed) causes a `Shipit::ReviewStack` to be created and queued for automatic provisioning from their own fork/branch, which the periodic queue worker will provision and later deploy using content from that unapproved branch — this is a path to executing attacker-influenced steps via `Command`/`PTY.spawn` on the deploy host, matching the Critical "RCE on the deploy host via Command/PTY.spawn" category. The blast radius is scoped to each repository individually configured this way; it does not cross-tenant automatically, but is repeatable per PR (each new labelless PR against such a repo creates a new stack/environment).

### Likelihood Explanation
This requires a specific, non-default repository configuration: `review_stacks_enabled: false` combined with `provisioning_behavior: prevent_with_label` and a configured `provisioning_label_name`. This is a plausible operator mistake (e.g., someone disabling the review-stacks toggle in the UI without also switching `provisioning_behavior` back to something inert), since the UI/docs suggest `review_stacks_enabled` is the master switch. Attacker cost is minimal — opening a PR against a public/forkable repo with this config, no label required. The existing test suite (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`) tests `provisioning_enabled: false` only against `allow_all`, never against `prevent_with_label`/`allow_with_label`, so this specific combination is untested and the bug was not caught. [7](#0-6) 

### Recommendation
Parenthesize `provision?` explicitly so `review_stacks_enabled` gates all branches:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to the analogous `unarchive?`/`archive?`-style predicates in `reopened_handler.rb`, `labeled_handler.rb`, and `unlabeled_handler.rb` where relevant (verify precedence there too).

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does not create stacks for prevent_with_label repos when review_stacks_enabled is false" do
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
Before the fix, this test fails: a `Shipit::ReviewStack` is created and `awaiting_provision?` becomes true despite `review_stacks_enabled: false`, demonstrating that the equality `repository.review_stacks_enabled == true` required for provisioning does not hold, yet provisioning proceeds anyway.

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

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
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
