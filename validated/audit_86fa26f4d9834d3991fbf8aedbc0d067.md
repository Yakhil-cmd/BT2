### Title
Label-driven `unarchive!` re-triggers provisioning of attacker-controlled PR branch without re-validating why the stack was archived - (File: `app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb`, `app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb`)

### Summary
`LabeledHandler#unarchive?` and `ReviewStackAdapter#unarchive!` decide whether to re-provision a review stack purely from the current label state of the PR (`provisioning_label_name` present/absent combined with `provisioning_behavior`), with no check on *why* or *by whom* the stack was previously archived. Any actor able to add the provisioning label to an open PR (per the question's stated precondition) can unarchive and re-enqueue provisioning/execution for that PR's branch, regardless of whether an operator archived it deliberately as a security block.

### Finding Description
The claimed binding is: `stack.archived? == false` should only become true again when a user *currently authorized* to approve provisioning re-approves the stack — not merely when the PR's label set matches the configured pattern again.

Tracing the code:
- `respond_to_label_change?` gates on `params.action == "labeled"`, `pull_request_state == "open"`, `repository.review_stacks_enabled`, and `(archive? || unarchive?)` [1](#0-0) .
- `unarchive?` is computed purely from `repository.provisioning_behavior_allow_with_label?`/`_prevent_with_label?` and `pull_request_has_provisioning_label?`, which only inspects `params.pull_request.labels` from the incoming webhook payload [2](#0-1) .
- `handle` calls `stack.unarchive!` whenever `unarchive?` is true, with no reference to who archived the stack or when [3](#0-2) .
- `ReviewStackAdapter#unarchive!` looks up the stack by `environment` (derived only from `pr#{params.number}`), checks `stack.archived?`, and if true re-enqueues `Shipit::ReviewStackProvisioningQueue.add(stack)` and calls `stack.unarchive!` inside a transaction — again with no distinction between an archive caused by label removal versus an operator's manual archive via `StacksController#update_archived` [4](#0-3) .
- The operator-initiated archive path (`StacksController#update_archived`) sets the same `archived`/`archived_since` state with no additional flag (e.g., "locked-by-operator") that would differentiate it from a label-driven archive [5](#0-4) .
- Re-enqueuing via `ReviewStackProvisioningQueue.add` and `unarchive!` triggers the provisioning state machine (`provision` event → `stack.provisioner.up`), which executes the PR's branch content through the configured `ProvisioningHandler` [6](#0-5) .

Because the `archived` boolean is a single undifferentiated state, and the only gate to leave it is the current label state on the PR, any principal with permission to add the provisioning label to their own open PR (a precondition explicitly granted by the question) can flip `archived?` back to `false` and cause `Shipit::ReviewStackProvisioningQueue` to re-run provisioning against whatever content is currently on that branch — including content pushed *after* the operator's manual archive. No code path re-validates repository maintainer approval, checks `archived_since` age, or requires a distinct "unlock" action separate from the label toggle. `force_github_authentication`, `verify_webhook_signature`, and the `ExplicitParameters` schema on `LabeledHandler` only validate that the webhook is a legitimately signed GitHub event for the labeled repository — they do not (and cannot) enforce that the label-adder is authorized to override a security archive, and no application-level check fills that gap.

### Impact Explanation
Re-provisioning executes the provisioner (`stack.provisioner.up`, ultimately a `Command`/`PTY.spawn`-backed execution) against the PR branch's current content on the Shipit deploy host, for the repository that owns the review stack. Because unarchiving is driven solely by the current label state rather than by re-approval, an operator's decision to archive a stack "for a security reason" provides no durable protection: any subsequent labeled webhook with the qualifying label state (attacker-controlled, per the given precondition) undoes it and re-triggers execution. This is scoped to the attacker's own PR/stack (not cross-tenant), but it defeats the archive-as-a-block workflow and causes unauthorized code execution/provisioning on the host for that repository, matching the "Critical: RCE on deploy host via Command/PTY.spawn" category. It is repeatable: the attacker can toggle the label off/on indefinitely, and each transition re-triggers `archive!`/`unarchive!` and re-provisioning.

### Likelihood Explanation
Requires `review_stacks_enabled == true` and `provisioning_behavior == :allow_with_label`, both legitimate, common configurations for review-stack-enabled repositories. It also requires the attacker to be able to add/remove the provisioning label on their own PR — the question states this as a precondition, but on stock GitHub, label mutation on a PR generally requires triage/write access to the base repository, not mere PR authorship from a fork; if that precondition doesn't hold in a given deployment, the attack is not reachable. Given the precondition as stated, attacker cost is a single webhook (real GitHub label toggle), and the exploit is reliably repeatable.

### Recommendation
Track archive provenance separately from the label-driven state (e.g., a `manually_archived`/`archived_by` distinction, or reuse the existing `lock`/`unlock` mechanism as a hard block), and have `LabeledHandler#unarchive?`/`ReviewStackAdapter#unarchive!` refuse to unarchive (or require explicit operator action) when the stack was archived through the manual/operator path rather than through a prior label removal.

### Proof of Concept
1. Configure a `Repository` with `review_stacks_enabled: true` and `provisioning_behavior: :allow_with_label`.
2. Create a `ReviewStack` for a PR, then have an operator call `stack.archive!(operator_user)` directly (simulating `StacksController#update_archived`), asserting `stack.archived? == true`.
3. Send a `labeled` webhook payload for the same PR/repo with `pull_request.labels` containing `repository.provisioning_label_name`, through `LabeledHandler.new(params).process` (or the webhooks controller entry point), with `sender.login` set to the attacker's GitHub login.
4. Assert `stack.reload.archived? == false` and that `Shipit::ReviewStackProvisioningQueue` contains the stack (i.e., provisioning was re-enqueued), demonstrating that a label webhook alone — with no operator re-approval — reversed the operator's security archive and re-triggered provisioning.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L90-97)
```ruby
          def unarchive?
            (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
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

**File:** app/controllers/shipit/stacks_controller.rb (L136-144)
```ruby
    def update_archived
      return unless params[:stack][:archived].present?

      if params[:stack][:archived] == "true"
        @stack.archive!(current_user)
      elsif @stack.archived?
        @stack.unarchive!
      end
    end
```

**File:** app/models/shipit/review_stack.rb (L45-77)
```ruby
    state_machine :provision_status, initial: :deprovisioned do
      state :provisioned
      state :provisioning
      state :deprovisioning
      state :deprovisioned

      event :provision do
        transition deprovisioned: :provisioning
      end

      event :provision_success do
        transition provisioning: :provisioned
      end

      event :provision_failure do
        transition provisioning: :deprovisioned
      end

      event :deprovision do
        transition provisioned: :deprovisioning
      end

      event :deprovision_success do
        transition deprovisioning: :deprovisioned
      end

      event :deprovision_failure do
        transition deprovisioning: :provisioned
      end

      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
      end
```
