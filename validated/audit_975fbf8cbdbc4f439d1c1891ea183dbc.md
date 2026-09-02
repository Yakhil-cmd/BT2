### Title
`provision?` operator-precedence bug bypasses `review_stacks_enabled` for `prevent_with_label` repos - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`OpenedHandler#provision?` is written as `A && B || C || D`, which Ruby parses as `(A && B) || C || D`. `review_stacks_enabled` (`A`) is only ANDed with the `allow_all?` branch (`B`); it is never combined with the `prevent_with_label` branch (`D`). Consequently, any unprivileged GitHub user can open a labelless pull request against a repository configured with `provisioning_behavior: prevent_with_label` even when `review_stacks_enabled` is `false`, and Shipit will still create and provision a `ReviewStack` from `params.pull_request.head.ref`.

### Finding Description
The binding that should hold is: `repository.review_stacks_enabled == true` for any review-stack to be provisioned from a pull request. Tracing `provision?`: [1](#0-0) 

Due to Ruby operator precedence, this evaluates as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. When `review_stacks_enabled` is `false` and `provisioning_behavior` is `prevent_with_label`, the first clause is `false`, but the third clause `(prevent_with_label? && !has_label?)` is independent of `review_stacks_enabled` and evaluates `true` for any labelless PR. `respond_to_pull_request_opened?` then returns `true`: [2](#0-1) 

`process` then unconditionally calls `ReviewStackAdapter#find_or_create!`: [3](#0-2) 

`create!` builds the stack directly from attacker-controlled webhook fields, including `branch: params.pull_request.head.ref` (the attacker's own fork branch), and immediately enqueues it for provisioning: [4](#0-3) 

The provisioning queue's default guard (`ProvisioningHandler::Base#provision?`) is hardcoded `true`, so nothing downstream re-checks `review_stacks_enabled` before `stack.provision` runs: [5](#0-4) [6](#0-5) 

Once provisioned, this stack will run tasks (deploy/provision steps) sourced from `shipit.yml` on the attacker's own unapproved branch — the branch was never vetted by an authorized Shipit user, breaking the intended binding that only `review_stacks_enabled` repos permit branch-driven stack creation and step execution.

None of the existing guards catch this: webhook signature verification (`verify_signature`/`GitHubApp#verify_webhook_signature`) only proves the payload came from GitHub for a repo the attacker legitimately owns/controls (a fork), it does not enforce `review_stacks_enabled`; the `ExplicitParameters` schema only validates payload shape; there is no `User#authorized?`/`require_permission!` check in this webhook path since it's unauthenticated by design (webhooks aren't user sessions); and `Repository` model validations don't touch `provisioning_behavior` combined with `review_stacks_enabled`.

### Impact Explanation
An attacker who owns/forks a repository configured with `provisioning_behavior: prevent_with_label` (a label configured) and `review_stacks_enabled: false` can open a labelless pull request to cause Shipit to create a `Shipit::ReviewStack` bound to their arbitrary head branch and enqueue it for provisioning — bypassing the operator's explicit decision to disable review stacks for that repository. Whatever the provisioning/task execution pipeline subsequently runs against that branch's `shipit.yml` executes attacker-controlled commands via `Command`/`PTY.spawn` on the deploy host, i.e., RCE using content the attacker fully controls and that was never approved by an authorized Shipit user. This is repeatable per pull request/branch and scoped to any repository misconfigured this way, matching the Critical severity bar (RCE on the deploy host via unapproved code).

### Likelihood Explanation
Requires only a repository configured with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false` (a plausible, non-exotic misconfiguration a Shipit operator might set expecting review stacks to be fully off) plus an attacker able to open a PR (or from their own fork) with no label. No secrets, tokens, or elevated GitHub permissions are needed — cost is a single PR open event. This is fully attacker-triggerable and repeatable.

### Recommendation
Fix the boolean grouping in `provision?` so `review_stacks_enabled` gates every branch, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (
      repository.provisioning_behavior_allow_all? ||
      (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
      (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
    )
end
```

### Proof of Concept
Minitest plan (based on existing `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` structure):
1. Create a `Shipit::Repository` fixture with `provisioning_behavior: :prevent_with_label` and `review_stacks_enabled: false`, with a `provisioning_label_name` configured.
2. Build an `opened` pull_request webhook payload with `labels: []` (no provisioning label) and `pull_request.head.ref` set to an attacker-chosen branch name.
3. Invoke `OpenedHandler.new(params).process` (or dispatch through the webhook processing path).
4. Assert, before tracing: `repository.review_stacks_enabled == false` (left side of the binding) — provisioning should never occur.
5. Assert, after processing: a `Shipit::ReviewStack` was created for that repository/environment (`assert stack.present?`), and `stack.awaiting_provision?` is `true`, and `stack.branch == params.pull_request.head.ref` — demonstrating the right side (`review_stacks_enabled == true` required) diverges from the enforced left side, proving the bypass.

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
