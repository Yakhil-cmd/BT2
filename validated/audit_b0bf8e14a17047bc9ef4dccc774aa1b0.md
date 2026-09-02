### Title
`provision?` operator-precedence bug bypasses `review_stacks_enabled` gate for label-based provisioning - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` combines `repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?` with two additional `||`-joined clauses that never reference `review_stacks_enabled`. In contrast, the sibling `LabeledHandler#respond_to_label_change?` explicitly ANDs `review_stacks_enabled` across all cases. As a result, a repository with `review_stacks_enabled == false` but `provisioning_behavior == 'allow_with_label'` will still have `provision?` return `true` for any pull request carrying the configured label, and `process` unconditionally calls `ReviewStackAdapter#find_or_create!`.

### Finding Description
Broken binding: the code implies `repository.review_stacks_enabled == true` is required before any `ReviewStack` provisioning, but tracing `provision?`: [1](#0-0) 

shows Ruby precedence groups the expression as:
```
(repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?) ||
(repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
(repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```
`review_stacks_enabled` is only referenced in the first disjunct. If `review_stacks_enabled == false` but `provisioning_behavior_allow_with_label? == true` and the PR carries the matching label, the second disjunct alone evaluates to `true`, making `provision?` return `true` regardless of the `review_stacks_enabled` value.

`process` then calls this without any further gate: [2](#0-1) 

`respond_to_pull_request_opened?` only checks `params.action == "opened" && provision?` — no separate `review_stacks_enabled` check exists at that layer either: [3](#0-2) 

`ReviewStackAdapter#find_or_create!` unconditionally creates the stack via `scope.create!` inside a transaction, with `scope: repository.review_stacks` (the association, not gated by the enabled flag): [4](#0-3) [5](#0-4) 

For comparison, `LabeledHandler#respond_to_label_change?` correctly ANDs `review_stacks_enabled` across the whole gate: [6](#0-5) 

Attacker path: any GitHub user opens a pull request against a target repository from a fork (or via a webhook simulating this, though webhook signature verification is a separate control not disproven here — the finding concerns the authorization logic once the event is processed), applies/has the label matching `repository.provisioning_label_name` on their own PR (label application on one's own fork/PR requires no special repo permission when the repository allows public PRs with labels, or the attacker's PR triggers `opened` with labels already present in the payload). This causes `Shipit::ReviewStack.count` to increase and a stack to be queued for provisioning on a repository whose operator explicitly set `review_stacks_enabled = false`.

No existing guard (`ExplicitParameters` schema, `drop_unhandled_event`, model validations) checks `review_stacks_enabled` at any other point in this call chain for `OpenedHandler`.

### Impact Explanation
An operator who disabled review stacks (`review_stacks_enabled == false`) still gets a `Shipit::ReviewStack` created and queued for provisioning whenever `provisioning_behavior == 'allow_with_label'` and a PR carries the matching label — an unauthorized record write and provisioning trigger on a repository that never opted in. This is repeatable per pull request/repository matching this configuration combination (any repo with `provisioning_behavior_allow_with_label` set while `review_stacks_enabled` is false — an operator misconfiguration/inconsistent-state scenario) and constitutes unauthorized `ReviewStack` creation and provisioning, matching the "record written for a repository that did not authenticate/authorize it" Critical impact category.

### Likelihood Explanation
Requires a specific repository configuration state: `review_stacks_enabled == false` combined with `provisioning_behavior == 'allow_with_label'` (or `prevent_with_label` for the third clause, though that clause is unconditional-label-absence not label-presence). This is a real, reachable state if an operator disables review stacks without resetting `provisioning_behavior`, since `review_stacks_enabled` and `provisioning_behavior` appear to be independently settable fields (see `provisioning_behavior` enum and `review_stacks_enabled` boolean in `Shipit::Repository`). Attacker cost is minimal: open a PR with a label, no privileged token or secret needed.

### Recommendation
Fix operator precedence in `provision?` by parenthesizing so `review_stacks_enabled` gates all disjuncts:
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
In a minitest test (would go under `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, out of scope to write here but described):
1. Build/stub a `Shipit::Repository` with `review_stacks_enabled: false`, `provisioning_behavior: 'allow_with_label'`, `provisioning_label_name: 'deploy-preview'`.
2. Construct `OpenedHandler` params with `action: 'opened'`, a `pull_request.labels` array containing `{ name: 'deploy-preview' }`, and repository `full_name` matching the stubbed repository.
3. Assert `handler.send(:provision?) == true` even though `repository.review_stacks_enabled == false` (the broken binding, both sides recorded: expected `false` from the gate, actual `true`).
4. Call `handler.process` and assert `Shipit::ReviewStack.count` increased by 1, proving unauthorized stack creation.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-21)
```ruby
          def find_or_create!
            stack || create!
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```
