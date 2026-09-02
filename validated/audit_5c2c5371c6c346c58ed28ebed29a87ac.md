### Title
Operator-precedence bug in `provision?` lets `prevent_with_label` PRs bypass `review_stacks_enabled` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` combines `review_stacks_enabled` with `provisioning_behavior_allow_all?` using `&&`, but the two later `||` clauses for `allow_with_label` and `prevent_with_label` are not ANDed with `review_stacks_enabled` due to Ruby operator precedence. As a result, a repository configured with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false` will still auto-provision a review stack for any opened pull request that omits the provisioning label.

### Finding Description
The intended binding is: a stack is created only if `repository.review_stacks_enabled == true`. The actual code is: [1](#0-0) 

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` binds tighter than `||` in Ruby, this parses as:

`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)`

`review_stacks_enabled` is scoped only to the `allow_all?` term; it is not applied to the `allow_with_label?` or `prevent_with_label?` branches. So when `review_stacks_enabled: false` and `provisioning_behavior: prevent_with_label`, opening a PR without the provisioning label makes `provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?` evaluate to `true`, and `provision?` returns `true` regardless of the disabled flag.

`process` then unconditionally calls `ReviewStackAdapter#find_or_create!`, which calls `create!`, persisting a new `Shipit::ReviewStack`/`Shipit::Stack` and enqueuing it via `Shipit::ReviewStackProvisioningQueue.add(stack)` for asynchronous provisioning: [2](#0-1) [3](#0-2) 

Attacker's exact PR: any GitHub user who can open a PR on the target repository (this includes fork-based PRs, since GitHub sends `pull_request` "opened" webhooks for those too), leaving `labels: []`. No secrets or Shipit privileges are needed — `verify_signature`/webhook auth only validates that GitHub sent the payload, it does not gate this business-logic check, and none of the `ExplicitParameters` schema fields constrain `review_stacks_enabled`/`provisioning_behavior` (those are read from the `Repository` record, controlled by the operator, not the payload).

I confirmed via the existing test suite that no test exercises `provisioning_enabled: false` combined with `behavior: :prevent_with_label`; the only "does not create" tests for `prevent_with_label` use a label present with `provisioning_enabled` defaulted to `true`: [4](#0-3) . This gap in tests is consistent with the bug being unnoticed.

The same precedence bug also exists in the sibling handlers `LabeledHandler#unarchive?`, `UnlabeledHandler#unarchive?`, and `ReopenedHandler#unarchive?`, all of which use the identical pattern, but those are AND-ed with an outer `repository.review_stacks_enabled &&` guard in their `respond_to_*?` methods (e.g. `respond_to_pull_request_reopened?` at [5](#0-4) , and `respond_to_label_change?` in `labeled_handler.rb`/`unlabeled_handler.rb`), which correctly gates the whole thing regardless of the internal precedence bug. `OpenedHandler#respond_to_pull_request_opened?`, however, delegates entirely to `provision?` without any outer `review_stacks_enabled` check: [6](#0-5) , so `OpenedHandler` is the only handler where this precedence bug is actually exploitable.

### Impact Explanation
Any repository operator who disables `review_stacks_enabled` while previously (or currently) configuring `provisioning_behavior: prevent_with_label` will unknowingly have review stacks auto-created and auto-provisioned for every PR lacking the exclusion label. Given Shipit's documented review-stack provisioning flow executes deploy/provision commands via `Command`/`PTY.spawn` on the deploy host, an attacker able to open PRs on such a repository (including via a fork) can force creation and provisioning of a stack whose branch/environment they control, leading to command execution driven by attacker-controlled PR content on the deploy host. This matches "Critical – RCE on the deploy host" / "unauthorized stack creation," scoped to the specific repository whose configuration matches this precondition. It does not cross repository boundaries; each affected repository must independently have this exact misconfiguration.

### Likelihood Explanation
Requires a specific, non-default configuration precondition: `review_stacks_enabled: false` AND `provisioning_behavior: prevent_with_label`. This is a plausible real-world state — for example, an operator who wants to temporarily disable review-stack provisioning while retaining their `prevent_with_label` policy for later re-enablement — and nothing in the UI/model prevents this combination. Once that precondition exists, exploitation is trivial and repeatable: any unprivileged contributor opens a PR without the label; no rate limiting or additional authorization guards this action.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates all three branches, e.g.:

```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

Also add a regression test covering `review_stacks_enabled: false` with `provisioning_behavior: prevent_with_label` and an empty label set.

### Proof of Concept
```ruby
test "does not create stacks for prevent_with_label repos when review_stacks_enabled is false" do
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
Binding under test: `repository.review_stacks_enabled == false` should imply no `ReviewStackAdapter#create!`/`Shipit::Stack.count` change. Before the fix, `assert_no_difference` fails because `provision?` returns `true` and a stack is created despite `review_stacks_enabled: false`; after applying the recommended parenthesization, the assertion passes.

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

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L159-187)
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

          test "does not create stacks for repos what prevent_with_label when label is present" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L65-75)
```ruby
          def respond_to_pull_request_reopened?
            params.action == "reopened" &&
              unarchive?
          end

          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
