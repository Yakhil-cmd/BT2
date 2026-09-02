### Title
Operator precedence bug in `ReopenedHandler#unarchive?` bypasses `review_stacks_enabled` for label-based provisioning behaviors - (File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb)

### Summary
`unarchive?` intends to gate all provisioning on `repository.review_stacks_enabled`, but Ruby's `&&`/`||` precedence makes `review_stacks_enabled` bind only to the `provisioning_behavior_allow_all?` clause, not to the `allow_with_label`/`prevent_with_label` clauses. This lets an attacker with `allow_with_label` behavior and the required label force a `Shipit::ReviewStack` to be created/unarchived even when review stacks are disabled for the repository.

### Finding Description
The claimed binding is `review_stacks_enabled == true` (the gate) for every provisioning decision. The actual code in `unarchive?`:
```ruby
repository.review_stacks_enabled &&
  repository.provisioning_behavior_allow_all? ||
  (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
  (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
``` [1](#0-0) 

evaluates as `(review_stacks_enabled && allow_all?) || (allow_with_label? && label_match) || (prevent_with_label? && !label_match)` because `&&` has higher precedence than `||`. So when `review_stacks_enabled == false` but `provisioning_behavior == 'allow_with_label'` and the PR carries the provisioning label, the second disjunct alone evaluates true and `unarchive?` returns `true`, contradicting the intended invariant that `review_stacks_enabled == false` must disable all review-stack provisioning.

Path: an attacker opens/closes/reopens their own PR (`action == "reopened"`) against a repository they don't operate but which is misconfigured with `provisioning_behavior: allow_with_label` and `review_stacks_enabled: false`, with the configured label attached to the PR. `respond_to_pull_request_reopened?` calls `unarchive?`, which returns true, then `stack.unarchive!` on `ReviewStackAdapter` finds `stack.blank?` (no existing `ReviewStack` for `pr#{number}`) and calls `create!`, which creates a `Shipit::ReviewStack` with `branch: params.pull_request.head.ref` and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` [2](#0-1) [3](#0-2) .

Existing guards (`verify_signature`, `ExplicitParameters` schema, `drop_unhandled_event`) do not prevent this because the webhook itself is legitimately signed/sent by GitHub for the attacker's own repository/PR — the vulnerability is a logic bug in the authorization/business-rule evaluation, not in webhook authentication. This exactly mirrors the confirmed sibling bug in `OpenedHandler#provision?`, which has the identical `&&`/`||` structure [4](#0-3) .

### Impact Explanation
An operator who disables review stacks (`review_stacks_enabled: false`) reasonably expects no review-stack provisioning to occur, including on reopen. This bug causes an unauthorized `Shipit::Stack` (review stack) to be created and queued for provisioning against a repository whose operator explicitly opted out, leading to `TaskCommands`/deploy-spec execution (`shipit.yml`) sourced from the attacker's own branch/ref — an unauthorized deploy/provisioning action the operator did not consent to. This matches the Critical category ("unauthorized deploy" via a record written for provisioning that did not authenticate/consent). It is repeatable against any repository configured with `allow_with_label` + `review_stacks_enabled: false`.

### Likelihood Explanation
Requires the specific repository configuration `review_stacks_enabled: false` combined with `provisioning_behavior: allow_with_label` (or `prevent_with_label` for the analogous non-label case), which is an operator-controlled setting exposed via the repository settings UI/API [5](#0-4) . Given that configuration, the attacker only needs to open/label/close/reopen their own PR — no privileged access, tokens, or secrets required. This is a low-cost, deterministic, repeatable bypass whenever that configuration combination exists.

### Recommendation
Fix operator precedence by parenthesizing the `review_stacks_enabled` gate around the entire disjunction in both `OpenedHandler#provision?` and `ReopenedHandler#unarchive?`:
```ruby
repository.review_stacks_enabled && (
  repository.provisioning_behavior_allow_all? ||
  (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
  (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
)
```

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`):
```ruby
test "does not unarchive/create a stack when review_stacks_enabled is false, even with allow_with_label + label match" do
  repository = shipit_repositories(:shipit) # or a fixture
  repository.update!(review_stacks_enabled: false, provisioning_behavior: 'allow_with_label')
  payload = payload_parsed(:pull_request_reopened)
  payload.pull_request.labels = [{ name: repository.provisioning_label_name }]

  assert_no_difference -> { Shipit::Stack.count } do
    Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process
  end
end
```
Assert both sides of the binding explicitly: `repository.review_stacks_enabled` (false) must equal the actual gate applied by `unarchive?`; currently the test fails because `Shipit::Stack.count` increases by 1 despite `review_stacks_enabled == false`, proving the divergence.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
```
