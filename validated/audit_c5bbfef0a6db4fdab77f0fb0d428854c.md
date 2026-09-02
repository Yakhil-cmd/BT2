### Title
`review_stacks_enabled` is not enforced for `allow_with_label`/`prevent_with_label` provisioning due to `&&`/`||` operator precedence - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`provision?` in `OpenedHandler` is written as `repository.review_stacks_enabled && provisioning_behavior_allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. Because Ruby's `&&` binds tighter than `||`, `review_stacks_enabled` is only ANDed with the `allow_all?` clause; it is never evaluated against the `allow_with_label` or `prevent_with_label` branches. Any repository configured with `provisioning_behavior: prevent_with_label` (or `allow_with_label`) will provision review stacks from any opened pull request regardless of whether the operator has set `review_stacks_enabled: false`.

### Finding Description
The binding the code is supposed to guarantee is:
`repository.review_stacks_enabled == true` must hold before `provision?` can return `true`, for every provisioning behavior.

The actual code:
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. The last two disjuncts never reference `review_stacks_enabled` at all, so once an operator sets `provisioning_behavior: :prevent_with_label`, the `review_stacks_enabled` flag is dead code for that behavior — provisioning happens purely based on label presence/absence, independent of whether review stacks are supposed to be on or off for the repo.

`pull_request_has_provisioning_label?` checks `pull_request_label_names.include?(repository.provisioning_label_name)` [2](#0-1) . Label names in the parsed payload are constrained to `String` by the `ExplicitParameters` schema (`requires :name, String`) [3](#0-2) , so when `provisioning_label_name` is `nil` this check is always `false`, making `!pull_request_has_provisioning_label?` always `true` for `prevent_with_label`. More generally, for `prevent_with_label` with any configured label, an attacker simply needs to *not* add that label — the default state of any newly opened PR — to satisfy the branch.

Exploit flow: operator sets `provisioning_behavior: prevent_with_label` (with or without a `provisioning_label_name`) and `review_stacks_enabled: false` on a repository. Any unprivileged GitHub user opens a pull request on that repository (a `pull_request` webhook with `action: "opened"` is emitted to `POST /webhooks`). `respond_to_pull_request_opened?` → `provision?` evaluates the `prevent_with_label` disjunct to `true` since the PR carries no matching label, and `ReviewStackAdapter#find_or_create!` creates a `Shipit::ReviewStack` and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` [4](#0-3) , entirely bypassing the operator's intent to disable review stacks for that repository.

None of the existing guards prevent this: webhook signature verification and `ExplicitParameters` validate payload shape/authenticity but do not touch this business-logic condition; there is no code path that separately checks `review_stacks_enabled` before calling `ReviewStackAdapter`. The existing test suite only exercises `prevent_with_label` with `review_stacks_enabled` left at its (enabled) default [5](#0-4) , so this divergence is untested and unnoticed.

### Impact Explanation
For any repository whose operator selected `provisioning_behavior: :allow_with_label` or `:prevent_with_label` and set `review_stacks_enabled: false` (intending to disable automatic review-stack provisioning entirely), an unauthenticated/unprivileged pull-request opener can still force creation of a `Shipit::ReviewStack` record and enqueue it for provisioning via `Shipit::ReviewStackProvisioningQueue.add` [6](#0-5) . This is a write to persistent state (`ReviewStack`, associated `PullRequest`) for a repository whose configuration explicitly opted out, and it seeds the provisioning queue that will eventually run deploy/provision tasks (spawning `Command`/`Task` execution) for attacker-controlled branch refs. This is repeatable for every PR opened and for every repository configured this way, but it is confined to repositories that already opted into `allow_with_label`/`prevent_with_label` behaviors — it does not cross repository/tenant boundaries and does not itself leak credentials or achieve RCE by itself (it only queues provisioning that other guarded machinery executes). This best matches an authorization-bypass-of-configuration issue rather than the RCE/token-exfiltration/cross-tenant categories explicitly named as Critical, and is closer to an unauthorized state mutation (stack/queue entry created against operator intent) enabled purely by unprivileged PR activity.

### Likelihood Explanation
Preconditions: the repository operator must have configured `provisioning_behavior` to `allow_with_label` or `prevent_with_label` (not the default `allow_all`) and separately set `review_stacks_enabled: false`. Given that configuration, exploitation cost for the attacker is trivial — open a pull request (for `prevent_with_label`, simply don't add the configured label, which is the default state of any new PR). No secrets, sessions, or elevated permissions are needed, and the action is fully repeatable per PR.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates every branch:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the same fix to `Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler`, which shares the identical `provision?` structure [7](#0-6) .

### Proof of Concept
```ruby
test "does not create stacks for prevent_with_label repos when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false, # review_stacks_enabled: false
    behavior: :prevent_with_label,
    label: "pull-requests-label" # or nil
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = [] # no matching label -> prevent_with_label branch would provision

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Binding under test: `repository.review_stacks_enabled == false` should imply `provision? == false` for every `provisioning_behavior`. Before the fix, `provision?` evaluates to `true` (stack is created, assertion fails); after applying the recommended parenthesization, `provision?` evaluates to `false` and the assertion passes.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L29-31)
```ruby
              requires :labels, Array do
                requires :name, String
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L72-78)
```ruby
          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L1-4)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
```
