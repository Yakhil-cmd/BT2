### Title
`review_stacks_enabled` is not enforced for `allow_with_label`/`prevent_with_label` due to operator-precedence bug in `unarchive?` - (File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb)

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == false` implies "provisioner never invoked for this repository". This binding is **broken** in `ReopenedHandler#unarchive?`:

```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Ruby's `&&` binds tighter than `||`, so this evaluates as:
```
(review_stacks_enabled && provisioning_behavior_allow_all?) ||
(provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
(provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```
`review_stacks_enabled` only gates the first disjunct. If the repository is configured with `provisioning_behavior: allow_with_label` (or `prevent_with_label`) and `review_stacks_enabled: false`, the second (or third) disjunct can still be `true` purely from the PR's label state, which the unprivileged PR author fully controls. The identical pattern exists in `OpenedHandler#provision?` [2](#0-1) .

This is confirmed by contrast with `LabeledHandler`/`UnlabeledHandler`, where the same disjuncts (`archive?`/`unarchive?`) intentionally do **not** embed `review_stacks_enabled`; instead the enable-flag is applied once, correctly, as a top-level AND over the whole label-change response: `params.action == "labeled" && pull_request_state == "open" && repository.review_stacks_enabled && (archive? || unarchive?)` [3](#0-2) . `ReopenedHandler` (and `OpenedHandler`) diverge from this correct pattern by folding the enable check into only the first disjunct of the behavior logic.

Exploit flow: attacker owns/forks a repo tracked by Shipit with `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label` (an operator misconfiguration where the flag was toggled off but behavior/label settings were left in place — plausible since these are independent DB columns with no validation tying them together, per `app/models/shipit/repository.rb`). Attacker opens a PR, closes it (archiving the stack), adds the provisioning label, then reopens it. `ReopenedHandler#process` calls `stack.unarchive!` because `respond_to_pull_request_reopened?` returns true via `unarchive?`'s broken precedence [4](#0-3) . This calls `ReviewStackAdapter#unarchive!`, which enqueues `Shipit::ReviewStackProvisioningQueue.add(stack)` and calls `stack.unarchive!` [5](#0-4) . The cron task `Shipit::ReviewStackProvisioningQueue.work` (run periodically, `lib/tasks/cron.rake`) then calls `stack.provision` → `stack.provisioner.up`, invoking the host's custom `ProvisioningHandler#up` [6](#0-5) .

Existing guards do not catch this: there's no signature verification issue here (webhook auth is out of scope for this specific bug, as the flaw is in application logic post-authentication), and no model validation ties `review_stacks_enabled` to `provisioning_behavior` consistency.

### Impact Explanation
An unprivileged PR author on a repository the operator explicitly disabled for review-stack provisioning (`review_stacks_enabled: false`) can still trigger `ProvisioningHandler#up` for a stack named `pr#{number}` with a branch they fully control, by toggling a label and reopening/relabeling a PR. This causes unauthorized invocation of custom host infrastructure-provisioning code with attacker-influenced parameters (`stack.branch`, `stack.environment`), which for a Kubernetes-based `ProvisioningHandler` (per the engine's documented example) could create real cluster resources keyed by attacker-chosen values. This matches "a payload... mutating another's stack" / infra state that should not be created, given the operator's explicit `review_stacks_enabled: false` boundary is bypassed.

### Likelihood Explanation
Requires the specific repository misconfiguration: `review_stacks_enabled: false` combined with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (columns are independent and not cross-validated, so this state is reachable by an operator). Given that configuration, exploitation cost is trivial: adding/removing a label and reopening a PR, actions available to any user who can open PRs against the repo (including on forks, depending on repo settings) — no secrets or elevated Shipit roles required. Fully repeatable for any PR number, hence any environment name `pr#{number}` the attacker chooses via successive PRs.

### Recommendation
Fix the operator precedence in both `ReopenedHandler#unarchive?` and `OpenedHandler#provision?` by parenthesizing correctly, applying `review_stacks_enabled` as a top-level gate over the entire behavior disjunction, consistent with `LabeledHandler`/`UnlabeledHandler`:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb` (minitest, no live GitHub):
```ruby
test "does NOT unarchive/provision when review_stacks_enabled is false, even with allow_with_label + label present" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # operator disabled review stacks
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  Shipit::ReviewStackProvisioningQueue.expects(:add).never

  Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process

  assert stack.reload.archived?, "Expected stack to remain archived since review_stacks_enabled is false"
end
```
Assert both sides of the binding: `repository.review_stacks_enabled` is `false` (LHS) yet, without the fix, `stack.archived?` becomes `false` and `ReviewStackProvisioningQueue.add`/`stack.provisioner.up` is invoked (RHS ≠ "provisioner never invoked"), proving the divergence. After applying the recommended fix, the test passes because `unarchive?` correctly returns `false`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-93)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end

          def archive?
            (repository.provisioning_behavior_allow_with_label? && !pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && pull_request_has_provisioning_label?)
          end

          def unarchive?
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

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
      end
```
