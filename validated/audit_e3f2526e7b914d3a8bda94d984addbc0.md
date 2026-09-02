### Title
Operator-precedence bug bypasses `review_stacks_enabled` when `provisioning_behavior` is label-based, letting an unprivileged PR author trigger `stack.provision` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` (and the identical `ReopenedHandler#unarchive?`) evaluates `repository.review_stacks_enabled && repository.provisioning_behavior_allow_all? || (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) || (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)`. Because `&&` binds tighter than `||` in Ruby, `review_stacks_enabled` only gates the `allow_all` branch; it is never consulted for `allow_with_label` or `prevent_with_label` repositories. Combined with `ProvisioningHandler::Base#provision?` defaulting to `true`, a repository configured with `provisioning_behavior: allow_with_label` (or `prevent_with_label`) and `review_stacks_enabled: false` will still have its `ReviewStack` created, enqueued, and provisioned by `ReviewStackProvisioningQueue#work` → `stack.provision`.

### Finding Description
The binding under test is: `repository.review_stacks_enabled == true` must hold on every code path that reaches `stack.provision`.

Trace:
- Webhook `pull_request` "opened" event reaches `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler#process` [1](#0-0) , gated only by `respond_to_pull_request_opened?` → `provision?`.
- `provision?` is defined as:
`repository.review_stacks_enabled && repository.provisioning_behavior_allow_all? || (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) || (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)` [2](#0-1) 
  Ruby operator precedence parses this as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)`. `review_stacks_enabled` is syntactically isolated to the first disjunct only.
- If `repository.provisioning_behavior == "allow_with_label"` and `repository.review_stacks_enabled == false`, and the incoming PR carries the configured `provisioning_label_name` (an attacker who owns their fork PR can apply a label they control per the scoping rules), `provision?` still evaluates `true`, so `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` runs and creates/enqueues a `ReviewStack` with `awaiting_provision: true` (`Shipit::ReviewStack#enqueue_for_provisioning`) [3](#0-2) .
- `ReviewStackProvisioningQueue#work` later pulls this queued stack and calls `provision(stack)`, which only checks `stack.provisioner.provision?` [4](#0-3) .
- For any repository using the default provisioning handler, `ProvisioningHandler::Base#provision?` unconditionally returns `true` [5](#0-4) , so `stack.provision` fires the `provisioning:` state-machine transition and calls `stack.provisioner.up` [6](#0-5) .
- Nowhere in this chain — `OpenedHandler`, `ReviewStackAdapter`, `ReviewStack`, `ReviewStackProvisioningQueue`, or `ProvisioningHandler::Base` — is `review_stacks_enabled` re-checked once the behavior is `allow_with_label`/`prevent_with_label`. The identical flaw exists in `ReopenedHandler#unarchive?` [7](#0-6) . Note `LabeledHandler#respond_to_label_change?` correctly parenthesizes/AND's `review_stacks_enabled` across the whole condition [8](#0-7) , so only the "opened"/"reopened" paths are affected — but "opened" is the primary path from an attacker's PR to `stack.provision`.

Attacker request: attacker opens a pull request against a targeted repository configured with `provisioning_behavior: allow_with_label` and `review_stacks_enabled: false`, applying the repository's configured provisioning label to their own PR (label application permitted per the attacker capability list), and the "opened" webhook fires the flow above.

Existing guards do not help: `ExplicitParameters` schema only validates payload shape, not authorization; `drop_unhandled_event`/signature verification only ensure the webhook is genuinely from GitHub for that repo, not that provisioning is enabled; `Repository` validations only constrain `name`/`owner` format, not this boolean gate.

### Impact Explanation
An attacker can force Shipit to create and provision a `ReviewStack` (invoking `stack.provisioner.up`, which for real provisioning handlers can run infrastructure-provisioning commands/API calls) for a repository whose operator explicitly disabled review-stack provisioning (`review_stacks_enabled: false`). This is an authorization-bypass: a security control the repository owner configured is silently ignored whenever `provisioning_behavior` is `allow_with_label` or `prevent_with_label`, letting an unprivileged PR author trigger provisioning side effects (state transitions, provisioner invocation, associated resource creation) that should not occur. Blast radius is scoped to repositories using non-default provisioning behavior with `review_stacks_enabled: false`, but it is fully repeatable against any such repository/PR by any contributor able to open a PR and apply a label to it.

### Likelihood Explanation
Requires: (1) target repository has `provisioning_behavior` set to `allow_with_label` or `prevent_with_label`, and `review_stacks_enabled: false` — a plausible/valid, non-default administrative combination (e.g., an operator temporarily disabling review stacks while leaving the label-based policy configured); (2) attacker can open a PR and add/remove the configured label on it. No secrets, tokens, or elevated GitHub permissions are needed beyond what's already assumed for the attacker persona. The bug is a pure logic error in this engine's code, deterministic and repeatable on every matching webhook delivery.

### Recommendation
Fix the boolean grouping in `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` so `review_stacks_enabled` gates every branch, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the same parenthesization to `ReopenedHandler#unarchive?`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (new test)
test "does not create/provision stacks when review_stacks_enabled is false, even with allow_with_label match" do
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :allow_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Before the fix this assertion fails (a `Shipit::Stack` is created and enqueued for provisioning despite `review_stacks_enabled == false`); after applying the parenthesization fix it passes. A second end-to-end assertion can additionally stub `ReviewStackProvisioningQueue#work` to confirm `stack.provision` is never invoked for such a repository.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
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

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
      end
```

**File:** app/models/shipit/review_stack.rb (L103-107)
```ruby
    def enqueue_for_provisioning
      return if awaiting_provision

      update!(awaiting_provision: true)
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

**File:** app/models/shipit/provisioning_handler/base.rb (L21-23)
```ruby
      def provision?
        true
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```
