This confirms the operator precedence bug is real and exploitable. The `provision?` method in `PullRequest::OpenedHandler` uses Ruby's `&&`/`||` precedence such that `review_stacks_enabled` only gates the `allow_all?` clause, not the `allow_with_label?` or `prevent_with_label?` clauses.

### Title
`OpenedHandler#provision?` operator-precedence bug bypasses `review_stacks_enabled=false` for `allow_with_label`/`prevent_with_label` repos - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`PullRequest::OpenedHandler#provision?` combines `review_stacks_enabled` with the three provisioning-behavior checks using bare `&&`/`||`, and Ruby's operator precedence (`&&` binds tighter than `||`) causes `review_stacks_enabled` to gate only the `allow_all?` branch. Any repository configured with `review_stacks_enabled=false` and `provisioning_behavior=allow_with_label` (or `prevent_with_label`) will still dynamically create and enqueue `Shipit::ReviewStack` records for attacker-opened pull requests that carry (or omit) the configured label.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:

Intended: `provision? == review_stacks_enabled && (allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?))`

Actual code:
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Because `&&` has higher precedence than `||` in Ruby, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

`review_stacks_enabled` is only ANDed into the first disjunct. When `review_stacks_enabled=false` and `provisioning_behavior=allow_with_label`, the second disjunct `(allow_with_label? && has_label?)` is evaluated completely independently of `review_stacks_enabled`, so an attacker-labeled PR satisfies `provision?` even though the operator disabled review-stack provisioning for the repository. Same divergence applies to `prevent_with_label` when the label is absent.

`respond_to_pull_request_opened?` only checks `params.action == "opened" && provision?` [2](#0-1) , and `process` then calls `ReviewStackAdapter#find_or_create!`, which creates the `ReviewStack` and immediately calls `Shipit::ReviewStackProvisioningQueue.add(stack)` [3](#0-2) . `ReviewStackProvisioningQueue.add` unconditionally enqueues the stack (`stack.enqueue_for_provisioning`) [4](#0-3) , with no re-check of `review_stacks_enabled`. The background worker `ReviewStackProvisioningQueue#work` then calls `stack.provisioner.provision?` — a *different*, handler-level check unrelated to `review_stacks_enabled` — and if true (the default `ProvisioningHandler::Base#provision?` always returns `true` [5](#0-4) ), calls `stack.provision`, which triggers `stack.provisioner.up` via the state machine [6](#0-5) .

None of the existing guards catch this: there is no test that pairs `review_stacks_enabled: false` with `behavior: :allow_with_label`/`:prevent_with_label` plus a matching label — every existing "provisioning disabled" test in `opened_handler_test.rb` only pairs `provisioning_enabled: false` with `behavior: :allow_all` [7](#0-6) , which happens to still work correctly because `allow_all?` is the one branch that IS correctly gated. The bug is invisible to that test suite by construction, and only manifests in the other two behavior modes.

### Impact Explanation
An attacker who can open pull requests (or push a commit with the right label to their own fork/branch and reopen) against a repository whose operator explicitly disabled `review_stacks_enabled` but left `provisioning_behavior` at `allow_with_label`/`prevent_with_label` can force creation and provisioning of arbitrary `Shipit::ReviewStack` rows tied to their PR branch/environment, bypassing the operator's explicit opt-out. Each such stack is provisioned via the host application's registered `ProvisioningHandler#up`, which host applications commonly use to allocate real infra and run commands driven by the review stack's `shipit.yml`/environment. This is repeatable per-PR and independent of maintainer review — the count/identity of provisioned stacks no longer matches the count of PRs a maintainer explicitly approved, since the repository's global provisioning switch is silently ignored for two of the three behavior modes. This matches the Critical category: an unauthorized deploy/provisioning action executes for a repository that the operator configured to not do so.

### Likelihood Explanation
Preconditions are exactly a config combination the operator can legitimately choose: `review_stacks_enabled=false` with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label`. No secrets, sessions, or special GitHub permissions are needed — only the ability to open a PR (or label one, for `allow_with_label`) against the tracked repository, which is the baseline attacker capability assumed in this audit. This is fully repeatable across arbitrary PRs/repositories matching this configuration and costs nothing beyond opening PRs.

### Recommendation
Fix operator precedence with explicit parentheses so `review_stacks_enabled` gates all three behavior branches:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Add regression tests covering `review_stacks_enabled: false` crossed with each of the three `provisioning_behavior` values and both label-present/absent states.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` (illustrative, not to be placed under `test/` per audit scope but describing the reproducible check):
```ruby
test "does not create stacks when review_stacks_enabled is false, even for allow_with_label with label present" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Both sides of the equality: expected `Shipit::Stack.count` unchanged (operator disabled provisioning) vs. actual `Shipit::Stack.count` increases by 1 due to the precedence bug — the assertion fails against current code, demonstrating the divergence.

### Citations

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

**File:** app/models/shipit/provisioning_handler/base.rb (L21-23)
```ruby
      def provision?
        true
      end
```

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
      end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L96-107)
```ruby
          test "only provision stacks for repos with auto-provisioning enabled" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              provisioning_enabled: false,
              behavior: :allow_all
            )

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload_parsed(:provision_disabled_pull_request)).process
            end
          end
```
