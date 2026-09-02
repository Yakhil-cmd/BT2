### Title
`ReopenedHandler#unarchive?` operator-precedence bug bypasses `review_stacks_enabled` for allow_with_label/prevent_with_label repos - (File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb)

### Summary
`ReopenedHandler#unarchive?` intends `repository.review_stacks_enabled` to gate all three provisioning-behavior branches, but Ruby's `&&`/`||` precedence binds it only to the `allow_all?` branch. As a result, closing then reopening a PR on a repository with `review_stacks_enabled == false` and `provisioning_behavior == :allow_with_label` still unarchives/re-provisions the review stack as long as the attacker's own PR carries the provisioning label.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled` (value at reopen-time) == the boolean actually consulted inside `unarchive?`'s `allow_with_label` branch. Before evaluation, this equality *should* hold if the code intent (mirrored by `LabeledHandler`) were followed.

`app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb:70-75`: [1](#0-0) 

```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` has higher precedence than `||` in Ruby, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

`review_stacks_enabled` is only ANDed into the first disjunct. When `provisioning_behavior == :allow_with_label` and the PR carries the provisioning label, `unarchive?` returns `true` unconditionally, independent of `review_stacks_enabled`. This breaks the equality: the value actually consulted by the `allow_with_label` branch is a constant `true` given the label, not `repository.review_stacks_enabled`.

`respond_to_pull_request_reopened?` (`app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb:65-68`) compounds this — unlike `LabeledHandler#respond_to_label_change?`, which explicitly re-checks `repository.review_stacks_enabled` (`app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb:78-83`) as an independent conjunct outside of `archive?`/`unarchive?`, `ReopenedHandler` never independently checks `review_stacks_enabled` — it relies entirely on the broken `unarchive?`: [2](#0-1) 

Attacker exact request: an unprivileged PR author on a repository they control (or any public fork PR) adds the provisioning label to their own PR, then closes and reopens it (real `pull_request` webhook events `closed` then `reopened`, legitimately signed by GitHub — no forged signature needed since these are genuine actions on a repository the attacker authored the PR against). `ReopenedHandler#process` calls `stack.unarchive!` (`app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb:41-45`), which delegates to `ReviewStackAdapter#unarchive!` (`app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:37-50`). Since the precondition states an archived `ReviewStack` already exists for that PR number, the adapter enqueues `Shipit::ReviewStackProvisioningQueue.add(stack)` and calls `stack.unarchive!(user)`, re-provisioning the stack (`Command`/`TaskCommands` execution) even though the operator had disabled review stacks for the repository.

Existing guards do not prevent this: `verify_signature` only ensures the webhook genuinely originates from GitHub for that repository/organization — it says nothing about whether `review_stacks_enabled` should gate the action, and the attacker is not forging the signature, they are triggering real GitHub events through legitimate PR actions on their own PR. `ExplicitParameters` param schema validation and `drop_unhandled_event` are unrelated to this authorization check. No model validation enforces `review_stacks_enabled` at the `unarchive!`/provisioning layer — that enforcement is solely the job of the buggy `unarchive?` predicate.

### Impact Explanation
An attacker who is merely a PR author (no Shipit session, no maintainer role) can force re-provisioning of an already-archived review stack — including running `TaskCommands#perform` → `Command#start` provisioning steps — on a repository whose operator explicitly disabled review stacks (`review_stacks_enabled == false`). This is an authorization bypass of the repository's provisioning policy, leading to unauthorized command execution tied to the attacker's branch/PR. The repeatability is limited to repositories configured with `provisioning_behavior == allow_with_label` (or `prevent_with_label`) that also have a pre-existing archived `ReviewStack` for that PR number and `review_stacks_enabled == false`; it is not exploitable against arbitrary repositories without that specific configuration and preexisting archived stack. This matches "Critical — RCE on the deploy host via `Command`/`PTY.spawn`... an unauthorized deploy" to the extent that provisioning triggers real shell commands via `Command#start`, but the blast radius is scoped to the attacker's own PR's stack/branch, not cross-tenant.

### Likelihood Explanation
Requires a specific, non-default combination: `repository.review_stacks_enabled == false`, `repository.provisioning_behavior == :allow_with_label` (or `:prevent_with_label`), and — critically — a pre-existing archived `Shipit::ReviewStack` row for that exact PR number (this state is unusual once `review_stacks_enabled` is false, since normal `find_or_create!` paths for creating stacks are typically gated elsewhere). If this precondition holds (e.g., left over from when review stacks were previously enabled and later disabled), the attacker's only cost is adding a label and closing/reopening their own PR — both are actions any PR author can perform with zero privilege. Feasibility is high once the precondition is met, but the precondition itself is not attacker-controlled and depends on repository history/configuration.

### Recommendation
Fix the operator precedence in `unarchive?` by explicitly grouping `review_stacks_enabled` across all branches, e.g.:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Additionally, mirror `LabeledHandler#respond_to_label_change?`'s pattern in `respond_to_pull_request_reopened?` by independently checking `repository.review_stacks_enabled` before consulting `unarchive?`, for defense in depth.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`):
1. Create a `Shipit::Repository` with `provisioning_behavior: :allow_with_label`, `review_stacks_enabled: false`.
2. Create an archived `Shipit::ReviewStack` under that repository for `environment: "pr123"` (matching PR number 123), asserting `stack.archived? == true` beforehand.
3. Build a `reopened` webhook payload for PR #123 with a `labels` array containing the repository's `provisioning_label_name`.
4. Assert the binding before tracing: `repository.review_stacks_enabled == false` and expected consulted value for `allow_with_label` branch should also be `false` (per intended semantics) — i.e., `assert_equal repository.review_stacks_enabled, handler.send(:unarchive?)` should hold as `false == false`.
5. Call `Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.call(payload)`.
6. Assert `stack.reload.awaiting_provision?` (or equivalent unarchived state) is `true`, demonstrating the equality is violated in practice (`review_stacks_enabled == false` but unarchive proceeded), and that `Shipit::ReviewStackProvisioningQueue` received the stack.

### Citations

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
