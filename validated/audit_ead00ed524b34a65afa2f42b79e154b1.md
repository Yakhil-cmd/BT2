### Title
Operator-precedence bug in `OpenedHandler#provision?`/`ReopenedHandler#unarchive?` lets `review_stacks_enabled: false` repositories still create/unarchive review stacks and reach `ReviewStackProvisioningQueue.add` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb], [File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`OpenedHandler#provision?` and `ReopenedHandler#unarchive?` combine `repository.review_stacks_enabled` with the three provisioning-behavior checks using `&&`/`||` without parentheses. Because Ruby's `&&` binds tighter than `||`, the expression evaluates as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`, so the `allow_with_label` and `prevent_with_label` branches are never gated by `review_stacks_enabled` at all. A repository configured with `review_stacks_enabled = false` but `provisioning_behavior = allow_with_label`/`prevent_with_label` will still have PRs create/unarchive a `ReviewStack` and enqueue it via `Shipit::ReviewStackProvisioningQueue.add`.

### Finding Description
The intended binding is: `repository.review_stacks_enabled == true` for any review stack to be created/unarchived and queued via `Shipit::ReviewStackProvisioningQueue.add`.

In `OpenedHandler`: [1](#0-0) 
`provision?` is written as `repository.review_stacks_enabled && repository.provisioning_behavior_allow_all? || (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) || (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)`. Due to Ruby precedence this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)` — the second and third disjuncts do not reference `review_stacks_enabled` at all.

`ReopenedHandler#unarchive?` has the identical construction: [2](#0-1) 

`process` in both handlers gates only on this broken predicate before invoking `ReviewStackAdapter`: [3](#0-2) [4](#0-3) 

`ReviewStackAdapter#create!` and `#unarchive!` unconditionally call `Shipit::ReviewStackProvisioningQueue.add(stack)`: [5](#0-4) [6](#0-5) 

`ReviewStackProvisioningQueue.add` simply flags the stack `awaiting_provision: true`, and the background queue worker later calls `stack.provisioner.provision?` and, if true (the documented default when no host app `ProvisioningHandler#provision?` is registered), calls `stack.provision`, which triggers `stack.provisioner.up` and downstream task execution of `shipit.yml`: [7](#0-6) [8](#0-7) 

Root cause: missing parentheses around `review_stacks_enabled && ...` cause it to only gate the `allow_all` behavior, not `allow_with_label`/`prevent_with_label`. Contrast this with `LabeledHandler#respond_to_label_change?` and `UnlabeledHandler#respond_to_label_change?`, where `review_stacks_enabled` is a separate top-level `&&` term ANDed with the whole `(archive? || unarchive?)` group — correctly gating both label handlers: [9](#0-8) [10](#0-9) 

Attacker's exact PR: any GitHub user opens (or reopens, after it was previously archived) a pull request against a repository where the maintainer set `review_stacks_enabled = false` (intending to disable dynamic review stacks) but left/set `provisioning_behavior` to `allow_with_label` or `prevent_with_label` (e.g. a partial/legacy config, or if this is left as a non-`allow_all` default while toggling the enabled checkbox off). For `allow_with_label`, the attacker adds the configured label (or if `prevent_with_label`, does nothing / avoids the label) to their own PR — labels on one's own PR are attacker-controlled if they have write access to their own fork/PR conversation, or the condition can already be satisfied by an empty label set for `prevent_with_label`. `OpenedHandler#process` calls `ReviewStackAdapter#create!`, which creates the `ReviewStack` from `params.pull_request.head.ref` (attacker's branch) and immediately calls `ReviewStackProvisioningQueue.add`, despite `review_stacks_enabled == false`.

### Impact Explanation
The attacker gets a `ReviewStack` created and queued for provisioning on a repository whose operator explicitly disabled review-stack provisioning, using their own branch/PR content that will be checked out and have `shipit.yml` steps executed by the provisioning task once picked up by the background job — matching the Critical "unauthorized deploy... downstream of the queue for a stack that should never have existed" category from the prompt. This is repeatable against any repository under the affected misconfiguration and is attacker-triggerable purely by opening/reopening/labeling a PR, with no session, token, or team membership required.

### Likelihood Explanation
Requires the host repository to have `review_stacks_enabled = false` combined with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (not the default `allow_all`) — a plausible but non-default configuration state (e.g., an operator toggling "enabled" off without also resetting behavior, or leaving legacy label-based settings when disabling globally). Given that configuration, exploitation cost is a single unauthenticated PR open/reopen/label webhook event — no secrets or elevated privileges needed.

### Recommendation
Parenthesize the boolean expressions in `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` so `review_stacks_enabled` gates the entire disjunction: `repository.review_stacks_enabled && (repository.provisioning_behavior_allow_all? || (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) || (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))`.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, add:
```ruby
test "does not create/queue a review stack when review_stacks_enabled is false, even with allow_with_label + matching label" do
  repository = shipit_repositories(:shipit)
  repository.update!(
    review_stacks_enabled: false,
    provisioning_behavior: :allow_with_label,
    provisioning_label_name: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = [{ "name" => "pull-requests-label" }]

  Shipit::ReviewStackProvisioningQueue.expects(:add).never

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Binding under test: `repository.review_stacks_enabled` (== `false`) must equal the effective gate that permits `Shipit::ReviewStackProvisioningQueue.add(stack)` to be invoked (should also be `false`/never-called). With the current `&&`/`||` precedence bug, `Shipit::ReviewStackProvisioningQueue.expects(:add).never` fails because `add` is called, proving the divergence.

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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L9-37)
```ruby
    def self.add(stack)
      stack.enqueue_for_provisioning
    end

    def self.queued_stacks
      new.queued_stacks
    end

    def work
      queued_stacks.find_each(&method(:provision))
    end

    def queued_stacks
      @queued_stacks ||= Shipit::ReviewStack
                         .with_provision_status(:deprovisioned)
                         .where(awaiting_provision: true)
    end

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

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L79-84)
```ruby
          def respond_to_label_change?
            params.action == "unlabeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```
