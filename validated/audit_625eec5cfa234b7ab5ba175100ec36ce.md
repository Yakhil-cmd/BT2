### Title
`ReopenedHandler#unarchive?` reuses the same `&&`/`||` precedence bug as `OpenedHandler#provision?`, letting a reopened PR provision a review stack while `review_stacks_enabled` is `false` - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler#unarchive?` (the reopened-PR analogue of `OpenedHandler#provision?`) uses the identical boolean expression, which due to Ruby's `&&`/`||` precedence only ANDs `review_stacks_enabled` with the `allow_all?` branch, not with the `allow_with_label?`/`prevent_with_label?` branches. When a repository has `provisioning_behavior=allow_with_label` and `review_stacks_enabled=false`, reopening a labeled PR still passes the gate and triggers `ReviewStackAdapter#unarchive!`, which internally calls `create!` (or unarchives/re-queues an existing stack), invoking `ReviewStackProvisioningQueue.add` and eventually `ProvisioningHandler#up`.

### Finding Description
Intended binding: `review_stacks_enabled == effective_gate`, i.e., provisioning of a review stack should only ever happen when `repository.review_stacks_enabled` is `true`, regardless of which `provisioning_behavior` is configured.

Actual code in `unarchive?`: [1](#0-0) 

Because `&&` binds tighter than `||` in Ruby, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

So when `provisioning_behavior_allow_with_label?` is true and the PR carries the provisioning label, the expression evaluates to `true` **independent of `review_stacks_enabled`**. This is byte-for-byte the same defect present in `OpenedHandler#provision?`: [2](#0-1) 

Exploitable path for `ReopenedHandler`:
1. Repository is configured with `provisioning_behavior=allow_with_label` and `review_stacks_enabled=false` (an admin/operator setting meant to fully disable stack provisioning).
2. Attacker (PR author) opens a PR with the provisioning label, then closes it, then reopens it (a `reopened` webhook action from GitHub — a legitimate, correctly signed event).
3. `ReopenedHandler#process` calls `respond_to_pull_request_reopened?` → `unarchive?`, which evaluates true due to the precedence bug: [3](#0-2) 
4. `stack.unarchive!` on `ReviewStackAdapter` creates the stack if none exists, or re-queues/unarchives an existing (archived) one, and adds it to `ReviewStackProvisioningQueue`: [4](#0-3) 
5. Queued stacks eventually transition `deprovisioned → provisioning`, invoking `stack.provisioner.up`, i.e., the configured `ProvisioningHandler`: [5](#0-4) [6](#0-5) 

Existing guards do not stop this: webhook signature verification only authenticates that the payload originated from GitHub for this repository — it does not validate the semantic gating logic, and this is a real, legitimately signed `reopened` event. `ExplicitParameters` schema validation only checks payload shape. `Repository`'s validations only constrain `owner`/`name` format, not `provisioning_behavior`/`review_stacks_enabled` interaction. None of these guards address the operator-precedence bug in the boolean expression itself.

### Impact Explanation
This causes provisioning (or unarchiving/re-provisioning) of a review stack for a repository whose administrator explicitly disabled review-stack provisioning (`review_stacks_enabled=false`). Provisioning invokes the repository's configured `ProvisioningHandler#up`, which for real-world provisioners can execute commands/infrastructure actions on the PR's branch content. This is repeatable per PR lifecycle event (open → close → reopen → close → reopen…), and applies to any repository with the `allow_with_label`/`prevent_with_label` behaviors regardless of the disabled flag — not a one-off race but a persistent divergence between configured intent and enforced behavior. Impact is scoped to the affected repository itself (the same repository whose flag is bypassed); this is not shown to cross repository boundaries into other tenants' stacks/commits/teams. Given the rubric's Critical bar requires cross-tenant mutation, forged auth, secret exfiltration, or RCE via a demonstrated command execution path, and Sig High requires escalation into `Shipit.github_teams`, unauthenticated read of stack/task state, SSRF with credentials, or session fixation — this finding, while a genuine logic bug that defeats the `review_stacks_enabled` kill switch, is confined to unauthorized provisioning within the same repository whose owner controls both the webhook events and (via GitHub App installation) the provisioning behavior configuration. No cross-tenant or credential-exfiltration path was found in the traced code.

### Likelihood Explanation
Preconditions: repository must have `provisioning_behavior=allow_with_label` (or `prevent_with_label`) AND `review_stacks_enabled=false` — a specific, non-default configuration combination that an operator would need to set (this is a Shipit-side repository setting exposed via `repositories_controller.rb`/`settings.html.erb`, not attacker-controlled). Given that configuration exists, any GitHub user who can open/label/reopen a PR against the repository (fork-based contributor) can trigger it at will, with no elevated privileges, repeatedly.

### Recommendation
Fix the operator precedence in both `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` (and audit `LabeledHandler`/`UnlabeledHandler` for the same pattern) by parenthesizing the `review_stacks_enabled` check so it gates the entire expression:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
minitest in `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb` (existing file — extend it):
1. Create a `Repository` with `provisioning_behavior: "allow_with_label"`, `review_stacks_enabled: false`.
2. Build `params` for a `reopened` action, PR labeled with `repository.provisioning_label_name`.
3. Assert before: `repository.review_stacks_enabled == false`.
4. Invoke `ReopenedHandler.new(...).process` (or call `respond_to_pull_request_reopened?`/`unarchive?` directly).
5. Assert that `unarchive?` returns `true` and that a `Shipit::ReviewStack` record is created/unarchived and added to `ReviewStackProvisioningQueue` — demonstrating `review_stacks_enabled(false) != effective_gate(true)`, i.e., the binding is broken.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
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

**File:** app/models/shipit/review_stack.rb (L51-53)
```ruby
      event :provision do
        transition deprovisioned: :provisioning
      end
```

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
      end
```
