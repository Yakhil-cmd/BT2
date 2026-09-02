### Title
`provision?` ignores `review_stacks_enabled` for `prevent_with_label`/`allow_with_label` clauses, permitting ReviewStack creation when review stacks are disabled - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` only ANDs `repository.review_stacks_enabled` with the `provisioning_behavior_allow_all?` branch; the `allow_with_label` and `prevent_with_label` branches are evaluated independently and are never gated by `review_stacks_enabled`. As a result, a repository configured with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false` still auto-provisions a `ReviewStack` for any attacker-opened PR that omits the provisioning label.

### Finding Description
The claimed binding is: `provision? == true` should imply `repository.review_stacks_enabled == true`. Tracing `provision?`: [1](#0-0) 

Ruby operator precedence makes `&&` bind tighter than `||`, so this expression parses as three independent OR'd terms:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

Only the first term checks `review_stacks_enabled`. The second and third terms check `provisioning_behavior` and label presence exclusively. Therefore if `review_stacks_enabled == false`, `provisioning_behavior_prevent_with_label? == true`, and the PR carries no provisioning label, the third term evaluates `true && true == true`, so `provision?` returns `true` even though review stacks are disabled for that repository.

`respond_to_pull_request_opened?` calls `provision?` directly with no additional `review_stacks_enabled` check: [2](#0-1) 

`process` then unconditionally invokes `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!`: [3](#0-2) 

`find_or_create!` creates a `ReviewStack` bound to `params.pull_request.head.ref` (attacker-controlled branch) and enqueues it for provisioning: [4](#0-3) 

Exploit flow: an unprivileged attacker opens a pull request (no session, no token needed — this is a public webhook-triggered event) against a real repository they can PR into, where the repo happens to be configured `provisioning_behavior: prevent_with_label` with `review_stacks_enabled: false`. The attacker simply does not add the provisioning label (default state of any newly opened PR). This causes a `ReviewStack`/`Stack` to be provisioned from the attacker's `head.ref`, which will later execute the attacker's `shipit.yml`/deploy pipeline on the deploy host — despite the operator having explicitly disabled review-stack provisioning for that repository.

None of the existing guards intercept this: `verify_signature`/webhook signature checks only authenticate that GitHub sent the payload, not what the payload's semantic content authorizes; `ExplicitParameters` schema only validates payload shape; there is no model validation preventing this behavior/flag combination on `Repository`. The existing test suite (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`) never exercises `prevent_with_label` combined with `review_stacks_enabled: false` — every behavior test uses the `provisioning_enabled: true` default of the `configure_provisioning_behavior` helper, so this gap was untested. [5](#0-4) 

### Impact Explanation
An unauthorized `ReviewStack` (and underlying `Stack`) is created and queued for provisioning for a repository whose operator explicitly disabled review-stack auto-provisioning (`review_stacks_enabled: false`). The stack is bound to the attacker's PR branch, meaning the attacker's `shipit.yml` and code will be provisioned/executed by Shipit's deploy pipeline on the deploy host — a record/resource created and code executed for content the operator did not authorize for stack creation. This is repeatable against any repository configured with `provisioning_behavior_prevent_with_label` and `review_stacks_enabled: false`, simply by opening PRs without the provisioning label. This matches the Critical impact category: unauthorized ReviewStack creation leading to execution of attacker-controlled deploy configuration.

### Likelihood Explanation
Preconditions required are entirely on the repository side, not the attacker: a repository must have `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false`. This is a legitimate, plausible operator configuration (e.g., an operator wants "no auto-provisioning" but leaves `prevent_with_label` set, believing the label logic still applies only when enabled). Given that configuration exists, attacker cost is zero: simply open a PR without adding the label — the default state. No secrets, tokens, or privileged roles required. Fully repeatable per PR/per repository matching this configuration.

### Recommendation
Add the `review_stacks_enabled` guard to all three branches (or factor it out), e.g.:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, add:
```ruby
test "does not create stacks when review_stacks_enabled is false even for prevent_with_label without a label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # review_stacks_enabled == false
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []  # no provisioning label present

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Assert both sides of the binding: `repository.review_stacks_enabled == false` (set via `provisioning_enabled: false`) and expect `Shipit::Stack.count` to be unchanged (i.e., `provision?` must return `false`). Running this against current code will show `Shipit::Stack.count` incrementing, proving `provision?` returns `true` while `review_stacks_enabled == false`, confirming the binding violation.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-98)
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

          def environment
            "pr#{params.number}"
          end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L159-196)
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

          def configure_provisioning_behavior(repository:, provisioning_enabled: true, behavior: :allow_all, label: nil)
            repository.review_stacks_enabled = provisioning_enabled
            repository.provisioning_behavior = behavior
            repository.provisioning_label_name = label
            repository.save!

            repository
          end
```
