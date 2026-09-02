### Title
`OpenedHandler#provision?` operator precedence bypasses `review_stacks_enabled` for `prevent_with_label` repositories - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::PullRequest::OpenedHandler#provision?` only ANDs `repository.review_stacks_enabled` with the `allow_all?` branch of its boolean expression due to Ruby's `&&`/`||` precedence, so the `allow_with_label?` and `prevent_with_label?` branches are evaluated independently of `review_stacks_enabled`. As a result, a repository operator who sets `review_stacks_enabled = false` with `provisioning_behavior = 'prevent_with_label'` will still have a `ReviewStack` created and provisioned whenever a PR is opened with no labels.

### Finding Description
The broken binding, stated as an equality that the code assumes but does not enforce: the intended behavior is `provision? == (repository.review_stacks_enabled && behavior_matches?)` for every behavior branch, but the actual code at [1](#0-0)  is:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` binds tighter than `||` in Ruby, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. `review_stacks_enabled` is scoped only to the first disjunct. When `repository.provisioning_behavior_prevent_with_label?` is `true` and no provisioning label is present, the third disjunct alone evaluates to `true` regardless of `review_stacks_enabled`.

Exploit flow: attacker opens a plain pull request (no labels) against a repository tracked by Shipit whose operator configured `provisioning_behavior: 'prevent_with_label'` and `review_stacks_enabled: false`. GitHub emits a legitimately signed `pull_request` `opened` webhook (webhook signature verification is not part of this bug and is assumed to pass normally). `respond_to_pull_request_opened?` calls `provision?`, which returns `true` via the third disjunct. `Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter#find_or_create!` then calls `create!` [2](#0-1) , which creates a `ReviewStack` record and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` [3](#0-2) . The queue worker later calls `stack.provisioner.provision?` and, if true, `stack.provision`, which triggers the repository's registered `ProvisioningHandler#up` [4](#0-3) , [5](#0-4) .

No existing guard prevents this: `respond_to_pull_request_opened?` only checks `params.action == "opened"`, and `pull_request_has_provisioning_label?` merely checks label membership; neither re-checks `review_stacks_enabled` for the `prevent_with_label` branch. The existing test suite does not cover this configuration combination — the closest test, "create stacks for repos what prevent_with_label when label is absent" [6](#0-5) , uses the default `provisioning_enabled: true` from `configure_provisioning_behavior` [7](#0-6) , so it never exercises `review_stacks_enabled: false`.

### Impact Explanation
An operator's explicit decision to disable review-stack auto-provisioning (`review_stacks_enabled = false`) is silently overridden whenever `provisioning_behavior` is `prevent_with_label`, purely because a PR lacks a specific label — the default state of any newly opened PR. This causes creation of a `ReviewStack` database record and triggers the repository's `ProvisioningHandler#up`, which in real deployments typically provisions infrastructure or runs external provisioning commands for the PR's branch. This is an unauthorized-provisioning bug: a record/action is created for a repository whose operator did not authorize it under the configured policy, driven merely by an unprivileged contributor opening a PR. It is repeatable for every PR opened against any repository sharing this misconfiguration (prevent_with_label + review_stacks_enabled=false), so the blast radius scales with however many tracked repositories use that specific combination.

### Likelihood Explanation
Preconditions are narrow but plausible: the target repository must be a Shipit-tracked repository configured with `provisioning_behavior_prevent_with_label? == true` and `review_stacks_enabled == false`. Given that combination, the attacker cost is zero beyond opening a normal, unlabeled pull request — no secrets, no elevated GitHub permissions, and no special webhook crafting are required, since it's a standard PR-opened event. The bug fires deterministically every time such a PR is opened.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates all three behavior branches:

```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, add:

```ruby
test "does not create stacks when review_stacks_enabled is false, even for prevent_with_label with no label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```

Assert both sides of the binding: `repository.review_stacks_enabled` is `false` and `repository.provisioning_behavior_prevent_with_label?` is `true` with empty labels — expected `provision?` should be `false` (equal to `review_stacks_enabled`), but with current code `provision?` returns `true` and `Shipit::Stack.count` increases, demonstrating the divergence.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L9-11)
```ruby
    def self.add(stack)
      stack.enqueue_for_provisioning
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

**File:** app/models/shipit/provisioning_handler/base.rb (L10-16)
```ruby
      def up
        # Intentionally a noop
      end

      def down
        # Intentionally a noop
      end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L159-172)
```ruby
          test "create stacks for repos what prevent_with_label when label is absent" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] = []

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L189-196)
```ruby
          def configure_provisioning_behavior(repository:, provisioning_enabled: true, behavior: :allow_all, label: nil)
            repository.review_stacks_enabled = provisioning_enabled
            repository.provisioning_behavior = behavior
            repository.provisioning_label_name = label
            repository.save!

            repository
          end
```
