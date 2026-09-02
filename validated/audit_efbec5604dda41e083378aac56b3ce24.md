### Title
`ReopenedHandler#unarchive?` bypasses `review_stacks_enabled` for label-gated behaviors due to `&&`/`||` operator precedence - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler#unarchive?` (and the structurally identical `OpenedHandler#provision?`) uses `review_stacks_enabled && allow_all? || (allow_with_label? && label) || (prevent_with_label? && !label)`. Because Ruby's `&&` binds tighter than `||`, `review_stacks_enabled` only gates the `allow_all` term, not the `allow_with_label`/`prevent_with_label` terms. If a repository's `provisioning_behavior` is `allow_with_label` or `prevent_with_label`, a `reopened` webhook re-provisions/unarchives the stack regardless of the value of `review_stacks_enabled`.

### Finding Description
Claimed binding: `unarchive? == true` should require `repository.review_stacks_enabled == true` AND a matching `provisioning_behavior` condition, for every branch.

Actual code: [1](#0-0) 
parses (per Ruby operator precedence) as:
```
(review_stacks_enabled && allow_all?) || (allow_with_label? && label_present) || (prevent_with_label? && !label_present)
```
`review_stacks_enabled` is only ANDed into the first disjunct. It is not required for the second or third disjuncts. `respond_to_pull_request_reopened?` [2](#0-1)  guards `process`, which then calls `stack.unarchive!` [3](#0-2) , delegating to `ReviewStackAdapter#unarchive!`, which either creates a new stack or re-queues an existing archived one for provisioning without any additional `review_stacks_enabled` check [4](#0-3) [5](#0-4) .

Exploit flow: attacker opens a PR against a repository configured with `provisioning_behavior: allow_with_label` (or `prevent_with_label`) — regardless of the current value of `review_stacks_enabled` — closes/reopens it (or the PR is closed by anyone), and sends a forged-looking but valid `reopened` webhook containing the label matching `provisioning_label_name` (attacker controls their own PR's labels). `unarchive?` evaluates true even if `review_stacks_enabled` is `false`, because that flag is scoped only to the `allow_all` disjunct by operator precedence, not to the whole expression. The same defect exists verbatim in `OpenedHandler#provision?` [6](#0-5) , `LabeledHandler#archive?`/`unarchive?` (correctly separately gated by `respond_to_label_change?` which explicitly checks `review_stacks_enabled` before calling `archive?`/`unarchive?` [7](#0-6) ), and `UnlabeledHandler` (same pattern as Labeled) [8](#0-7) . Notably, `LabeledHandler`/`UnlabeledHandler` are *not* vulnerable because they check `repository.review_stacks_enabled` as an independent top-level conjunct in `respond_to_label_change?` before ever calling `archive?`/`unarchive?`; `OpenedHandler` and `ReopenedHandler` fold the flag directly into the mis-parenthesized boolean expression, which is the actual root cause.

No other guard intercepts this: `verify_signature`/`GitHubApp#verify_webhook_signature` only validate that the payload came from GitHub for *some* repository the attacker can freely generate (opening/reopening their own PR), not that `review_stacks_enabled` is honored; `drop_unhandled_event` and `ExplicitParameters` only validate schema shape; there is no model-level revalidation of `review_stacks_enabled` in `ReviewStackAdapter`, `Stack#unarchive!`, or `ReviewStackProvisioningQueue`.

### Impact Explanation
The result is unauthorized creation/unarchival of a `Shipit::ReviewStack` and enqueuing for provisioning (`ReviewStackProvisioningQueue.add` → `awaiting_provision: true`) for a repository whose operator explicitly disabled dynamic review-stack provisioning (`review_stacks_enabled: false`), as long as `provisioning_behavior` is set to `allow_with_label` or `prevent_with_label`. This is a write the operator's configuration should have prevented. Whether this escalates further to actual command execution (`PTY.spawn`) depends on the host application's `ProvisioningHandler` subclass; the built-in `ProvisioningHandler::Base#up`/`#down` are no-ops [9](#0-8) , so RCE via `PTY.spawn`/`Command#start` is not demonstrable purely within this engine's own code without a host-defined handler that shells out — that part of the Critical framing in the question is not substantiated by code in this repo. What is substantiated and repeatable per-repository (any repo with `allow_with_label`/`prevent_with_label` configured) is the unauthorized stack provisioning/state mutation bypassing the disabled-review-stacks setting.

### Likelihood Explanation
Preconditions: repository must have `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (a normal, documented configuration, independent of `review_stacks_enabled`). No toggling between webhook deliveries is actually required — the bug is present any time these two settings coexist, since `review_stacks_enabled` never gates the label branches at all. Attacker cost is low: open/label a PR they control on any repo with this config, then trigger `reopened` (or rely on GitHub naturally emitting it when they reopen their own PR). Fully repeatable against any such repository.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the entire expression:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the identical fix to `OpenedHandler#provision?`.

### Proof of Concept
minitest in `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb` style:
```ruby
test "does NOT unarchive/provision stacks when review_stacks_enabled is false, even for allow_with_label with matching label" do
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :allow_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process
  end
end
```
Binding assertion: `repository.review_stacks_enabled == false` before and after must correspond to `Shipit::Stack.count` unchanged (`unarchive?` should be `false`). Running against current code, `unarchive?` evaluates `true` (label present, `allow_with_label?` true) and the assertion fails, proving the divergence.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-85)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L79-94)
```ruby
          def respond_to_label_change?
            params.action == "unlabeled" &&
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

**File:** app/models/shipit/provisioning_handler/base.rb (L10-16)
```ruby
      def up
        # Intentionally a noop
      end

      def down
        # Intentionally a noop
      end
```
