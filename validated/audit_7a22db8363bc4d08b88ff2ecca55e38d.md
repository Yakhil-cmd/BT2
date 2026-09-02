This confirms the vulnerability. In fact, there's an existing test at line 159-172 of `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` titled "create stacks for repos what prevent_with_label when label is absent" that already exercises this exact path (though it doesn't set `review_stacks_enabled: false`, it defaults to `true` via `configure_provisioning_behavior`'s `provisioning_enabled: true` default) — the missing case is precisely `review_stacks_enabled: false` combined with `prevent_with_label`, which the codebase's test suite does not cover.

### Title
Missing `review_stacks_enabled` check on `prevent_with_label` branch allows unauthorized stack creation from an unlabeled fork PR - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`Repository#provision?` in `opened_handler.rb` ORs three provisioning-behavior clauses, but only the first (`allow_all`) is gated by `repository.review_stacks_enabled`. Because `&&` binds tighter than `||` in Ruby, the third clause `(repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)` evaluates independently of `review_stacks_enabled`, so a repository with review stacks explicitly disabled still auto-creates a `Shipit::ReviewStack` whenever an attacker opens an unlabeled PR.

### Finding Description
The broken binding, stated as an equality that should hold but does not: `provision?` should equal `repository.review_stacks_enabled && (allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?))`, but the actual code at [1](#0-0)  is:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Due to Ruby operator precedence, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. The third disjunct never references `review_stacks_enabled`. When `review_stacks_enabled = false` and `provisioning_behavior = :prevent_with_label`, an attacker who opens a PR from their own fork with no labels causes `pull_request_has_provisioning_label?` to be `false`, making the third clause `true`, so `provision?` returns `true` even though the operator explicitly disabled review stacks for this repository.

Code path: `OpenedHandler#process` at [2](#0-1)  calls `respond_to_pull_request_opened?` → `provision?`, and on success instantiates `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!`. `ReviewStackAdapter#create!` builds the stack with `branch: params.pull_request.head.ref` taken verbatim from the attacker-controlled PR payload, with no additional check of `review_stacks_enabled`, per [3](#0-2) . The stack is then queued via `Shipit::ReviewStackProvisioningQueue.add(stack)` at [4](#0-3) .

The attacker's exact request: open a pull request (`action: "opened"`) from their own fork/branch against a tracked repository whose Shipit configuration has `review_stacks_enabled: false` and `provisioning_behavior: :prevent_with_label`, with no labels on the PR. GitHub sends a legitimately-signed webhook for this action (the attacker owns the PR/fork, so this is a normal, validly-signed event, not a forged webhook) to `POST /webhooks`. `verify_signature`/webhook signature checks pass because GitHub itself is delivering the event — none of `verify_signature`, `drop_unhandled_event`, or the `ExplicitParameters` schema constrain `provisioning_behavior` logic; they only validate payload shape and delivery authenticity, not this authorization decision. No existing guard (model validation, `EnvironmentVariables#permit`, `require_permission!`) checks `review_stacks_enabled` a second time in `ReviewStackAdapter`.

### Impact Explanation
A `Shipit::ReviewStack`/`Shipit::Stack` record is created and queued for provisioning for a repository whose operator explicitly opted out of review-stack automation (`review_stacks_enabled: false`), using a `branch` value fully controlled by the unprivileged PR author. Since review stacks provisioning subsequently checks out and runs the repository's `shipit.yml`-defined steps against that branch on the deploy host (via `Command`), an attacker-controlled branch can carry attacker-authored deploy steps, leading to code execution on the deploy host — this is the "authorized user" trust boundary bypass matching Critical severity (unauthorized stack creation triggering execution of attacker-supplied deploy steps). This is repeatable against any repository configured with `review_stacks_enabled: false` + `provisioning_behavior: :prevent_with_label` for every PR opened without the provisioning label, and does not require any credentials beyond the ability to open a PR on one's own fork.

### Likelihood Explanation
Preconditions: the target repository must already be tracked by Shipit and configured with `review_stacks_enabled: false` and `provisioning_behavior: :prevent_with_label` (an intentional "review stacks off" configuration choice by the repo's Shipit operator). Given that configuration, the attacker's cost is trivial — open a PR from a fork with no special label, which any GitHub user with fork/PR rights can do. No secrets, sessions, or elevated GitHub permissions are needed. The bug is fully deterministic and repeatable on every such PR.

### Recommendation
Fix operator precedence by making `review_stacks_enabled` gate all three clauses, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
Add a minitest to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` (existing file, following its established `configure_provisioning_behavior` helper pattern at lines 189-196):

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

Assert both sides of the binding: before the fix, `Shipit::Stack.count` differs by `+1` (bug: stack created despite `review_stacks_enabled == false`); after applying the recommended fix, `Shipit::Stack.count` differs by `0` (correct: `review_stacks_enabled == false` implies `provision? == false` regardless of `provisioning_behavior`).

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
