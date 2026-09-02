### Title
Operator precedence in `PullRequest::OpenedHandler#provision?` allows ReviewStack creation/provisioning when `review_stacks_enabled` is `false` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`provision?` intends to require `repository.review_stacks_enabled` be true for any provisioning path, but due to Ruby's `&&`/`||` precedence, the `review_stacks_enabled` check only gates the `allow_all` branch. The `allow_with_label` and `prevent_with_label` branches are unconditionally OR'd in, so an attacker's labeled pull request can trigger stack creation and queuing for provisioning even though the repository has review stacks disabled.

### Finding Description
The broken binding: the code intends `repository.review_stacks_enabled == true` to gate all provisioning decisions, but as written it only gates one disjunct.

`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb` lines 65-70: [1](#0-0) 

Ruby parses `&&` with higher precedence than `||`, so this expression is actually:

`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

Thus if `review_stacks_enabled == false` and `provisioning_behavior == "allow_with_label"` and the PR carries the configured `provisioning_label_name`, the second disjunct evaluates to `true` independently of `review_stacks_enabled`, making `provision?` return `true`.

`respond_to_pull_request_opened?` then permits `process` to call: [2](#0-1) 

which invokes `ReviewStackAdapter#find_or_create!` → `create!`, building a `ReviewStack` with `branch: params.pull_request.head.ref` (attacker-controlled, from their fork's branch) and then queuing it via `Shipit::ReviewStackProvisioningQueue.add(stack)`: [3](#0-2) 

No downstream guard re-checks `review_stacks_enabled`: `ReviewStack` (`app/models/shipit/review_stack.rb`) has no such validation, `ProvisioningHandler::Base#provision?` defaults to `true` unconditionally, and `ReviewStackProvisioningQueue#provision` only checks `stack.provisioner.provision?`, not the owning repository's `review_stacks_enabled` flag: [4](#0-3) [5](#0-4) 

The webhook signature check, `drop_unhandled_event`, and `ExplicitParameters` schema validation are irrelevant here — they authenticate that the webhook payload came from GitHub for a real PR, but do nothing to prevent the logic bug in `provision?`. The attacker's request is simply: fork the repository, push a branch, open a pull request, and attach the label configured in `repository.provisioning_label_name` (label names are visible in `Repository` settings/UI or discoverable) — no privileged Shipit session or secret is required, only ability to open a PR and apply a label to their own PR (label application permission is repo-owner-controlled, but on many repos external contributors or the PR author can self-apply existing labels, or a maintainer/bot could unintentionally do so; regardless, the label name matching is attacker-observable and the exploit condition is a pure logic defect independent of any secret).

### Impact Explanation
Once triggered, `ReviewStackAdapter#create!` creates a real `Shipit::ReviewStack` record and immediately enqueues it for provisioning, even though the target `Repository` never opted into review stacks (`review_stacks_enabled: false`). This stack's `branch` is the attacker's fork branch, meaning subsequent provisioning/deploy will pull `shipit.yml`/deploy steps from attacker-controlled code and execute them via the deploy pipeline (`Command#start` → `PTY.spawn`) on the deploy host — Critical impact (unauthorized stack creation/provisioning leading to command execution on the deploy host with attacker-supplied deploy configuration). This is repeatable against any repository configured with `provisioning_behavior: allow_with_label`, regardless of `review_stacks_enabled`, and does not require any Shipit credentials.

### Likelihood Explanation
Preconditions: target repository must have `provisioning_behavior` set to `allow_with_label` (or `prevent_with_label`, which has a symmetric bug where the `review_stacks_enabled` flag is likewise not enforced) with a non-`allow_all` behavior configured, and a `provisioning_label_name` set — while `review_stacks_enabled` is `false`. This is a plausible administrative configuration (e.g., an operator disables review stacks broadly but leaves stale `provisioning_behavior`/label settings from a prior configuration, or intends label-gating to be the sole control). Attacker cost is low: open a PR from a fork and apply/have the label applied to it. Repeatable per PR/branch against any such repository.

### Recommendation
Fix operator precedence in `provision?` so `review_stacks_enabled` gates every branch, e.g.:

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
1. Create a `Shipit::Repository` fixture/record with `review_stacks_enabled: false`, `provisioning_behavior: "allow_with_label"`, `provisioning_label_name: "deploy-preview"`.
2. Assert the binding before: `repository.review_stacks_enabled == false` (must hold) while `repository.provisioning_behavior_allow_with_label? == true`.
3. Build `payload_parsed(:pull_request_opened)` with `pull_request.labels = [{ name: "deploy-preview" }]` and `pull_request.head.ref` set to an attacker branch name, targeting this repository's `full_name`.
4. Instantiate `OpenedHandler` (or post to `/webhooks` with a validly signed test payload) and call `process`.
5. Assert `Shipit::Stack.count` increased by 1 and the new `ReviewStack.branch` equals the attacker-supplied `head.ref`.
6. Assert `Shipit::ReviewStackProvisioningQueue.queued_stacks` includes the created stack (i.e., `awaiting_provision == true`), proving provisioning was queued despite `repository.review_stacks_enabled == false`.
7. Assert this contradicts the intended invariant: expected `Shipit::Stack.count` unchanged and no queue entry when `review_stacks_enabled == false`, demonstrating the divergence caused by operator-precedence in `provision?`.

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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L27-37)
```ruby
    private

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
