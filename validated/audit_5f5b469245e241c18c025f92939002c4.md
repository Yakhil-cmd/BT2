This confirms the bug clearly: in `OpenedHandler#provision?`, the `LabeledHandler`'s sibling code explicitly checks `repository.review_stacks_enabled` as a top-level AND across all three provisioning behaviors (`respond_to_label_change?` at [1](#0-0) ), proving the intended binding is `review_stacks_enabled == true` required for ANY provisioning action regardless of `provisioning_behavior`. But `OpenedHandler#provision?` instead has the `&&` bound only to `provisioning_behavior_allow_all?` due to Ruby operator precedence, leaving `allow_with_label?` and `prevent_with_label?` branches completely unguarded by `review_stacks_enabled` [2](#0-1) .

### Title
`OpenedHandler#provision?` operator-precedence bug bypasses `review_stacks_enabled` for `allow_with_label`/`prevent_with_label` behaviors, letting any PR author trigger stack provisioning - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` combines `repository.review_stacks_enabled` with `provisioning_behavior_allow_all?` using `&&`/`||` without parentheses, so `review_stacks_enabled` only gates the `allow_all` branch and is silently ignored for `allow_with_label` and `prevent_with_label` repositories. Since `respond_to_pull_request_opened?` only checks `params.action == "opened" && provision?`, any external user who can open a pull request (and label it, for the `allow_with_label` case) can cause `ReviewStackAdapter#create!` to run and enqueue provisioning, even when the maintainer explicitly disabled review stacks (`review_stacks_enabled: false`).

### Finding Description
The intended binding, evidenced by the sibling `LabeledHandler#respond_to_label_change?` [1](#0-0) , is: `review_stacks_enabled == true` must hold for provisioning-adjacent actions to occur under ANY `provisioning_behavior`. In `OpenedHandler#provision?` [2](#0-1) , Ruby's operator precedence makes `&&` bind tighter than `||`, so the expression parses as:

`(repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?) || (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) || (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)`

The last two disjuncts never reference `review_stacks_enabled` at all. Thus for a repository configured with `provisioning_behavior: :prevent_with_label` and `review_stacks_enabled: false`, any PR opened without the provisioning label makes `provision?` return `true`. `respond_to_pull_request_opened?` then returns `true` [3](#0-2) , and `process` calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` [4](#0-3) , which creates a `ReviewStack` from attacker-controlled `params.pull_request.head.ref` [5](#0-4)  and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)`, ultimately transitioning the state machine to `provisioning` and calling `stack.provisioner.up` [6](#0-5) .

No existing guard intercepts this: `respond_to_pull_request_opened?` only checks `action == "opened"`; there is no `params.pull_request.user.login` or `params.sender.login` allowlist check anywhere in `OpenedHandler`; `Repository.from_github_repo_name` only requires the target repository to already be tracked by Shipit (an operator precondition, not an authorization check on the PR author) [7](#0-6) . Webhook signature verification (`verify_signature`/`drop_unhandled_event`, not shown here) only proves the event genuinely came from GitHub for that repository — it does nothing to validate the PR author's trust level, which is exactly the gap `review_stacks_enabled` is meant to close.

Note: the default `ProvisioningHandler::Base#provision?` returns `true` unconditionally [8](#0-7) , meaning nothing downstream re-validates whether provisioning should have been allowed; whether `provisioner.up`/`down` execute `Command`/`PTY.spawn`-based RCE depends on the concrete `ProvisioningHandler` subclass configured by the operator (out of scope of this file, but the standard `Shell` provisioner in this engine does shell out).

### Impact Explanation
Any external, fully unprivileged GitHub user who can open a pull request against a tracked repository can force `Shipit::ReviewStack` creation and enqueue provisioning even though the operator explicitly configured `review_stacks_enabled: false` — the exact control meant to gate this capability. Depending on the operator's `ProvisioningHandler` implementation, `stack.provisioner.up` triggers shell/`Command` execution against the attacker's branch/environment on the deploy host, matching the Critical "RCE on the deploy host via `Command`/`PTY.spawn`... or an unauthorized deploy" category. This is repeatable for every PR opened against any repository configured with `prevent_with_label` (trivially, by just not adding the label) or `allow_with_label` (by adding a label the attacker controls on their own PR) regardless of `review_stacks_enabled`.

### Likelihood Explanation
Preconditions: the target repository must already be onboarded into Shipit with `review_stacks` code active (i.e., `provisioning_behavior` set to `allow_with_label` or `prevent_with_label`) — this is a very plausible/common configuration since `allow_all` would be considered the risky path and operators are likely to choose the more conservative label-gated modes, not realizing `review_stacks_enabled` no longer applies. No secrets, sessions, or team membership are needed — attacker cost is a single PR open (and possibly self-applying a label on their own PR, which any PR author can do). Fully repeatable across every repository sharing this handler code.

### Recommendation
Fix the precedence bug by parenthesizing so `review_stacks_enabled` applies to the whole expression, matching `LabeledHandler`'s pattern:

```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
1. Create a `Repository` with `provisioning_behavior: :prevent_with_label`, `review_stacks_enabled: false`.
2. Build `payload_parsed(:pull_request_opened)` with `pull_request.user.login` set to a never-before-seen external login, `action: "opened"`, and no provisioning label in `pull_request.labels`.
3. Assert equality binding before: `repository.review_stacks_enabled` is `false` and expect `Shipit::ReviewStack.count` to remain `0` after invoking `OpenedHandler.new(payload).process`.
4. Run `OpenedHandler.new(payload).process`.
5. Assert `Shipit::ReviewStack.count == 1` (stack created) despite `review_stacks_enabled == false`, proving the equality `review_stacks_enabled == true` required for provisioning is violated — `provision?` returns `true` when it should return `false`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```

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

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
      end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/provisioning_handler/base.rb (L21-23)
```ruby
      def provision?
        true
      end
```
