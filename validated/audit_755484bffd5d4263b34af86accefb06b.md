### Title
Missing `review_stacks_enabled` gate in `OpenedHandler#provision?` allows unauthorized ReviewStack provisioning - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` combines `repository.review_stacks_enabled` with only the `allow_all?` clause via `&&`, then `||`s in the `allow_with_label?` and `prevent_with_label?` clauses without re-checking `review_stacks_enabled`. Due to Ruby operator precedence (`&&` binds tighter than `||`), a repository with `review_stacks_enabled: false` and `provisioning_behavior: prevent_with_label` will still provision a `ReviewStack` for any unlabeled pull request.

### Finding Description
The intended binding is: `repository.review_stacks_enabled == true` must hold for *every* provisioning branch. The actual code is: [1](#0-0) 

Ruby parses this as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

The third disjunct, `(repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)`, has no dependency on `review_stacks_enabled` at all. So for a repository with `review_stacks_enabled: false` and `provisioning_behavior: prevent_with_label`, opening a PR with zero labels makes `pull_request_has_provisioning_label?` false, `!false == true`, and `provisioning_behavior_prevent_with_label?` true — the whole expression evaluates to `true` even though `review_stacks_enabled` is `false`.

Call path: `OpenedHandler#process` calls `respond_to_pull_request_opened?` → `provision?` returns `true` → `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` → since no existing stack, `create!` runs `scope.create!(stack_attributes)` and enqueues `Shipit::ReviewStackProvisioningQueue.add(stack)`. [2](#0-1) [3](#0-2) 

Nothing else in the webhook path re-checks `review_stacks_enabled`: the `ReviewStack` model, `Repository#review_stacks` association, and `ReviewStackProvisioningQueue.add` do not gate on this flag; the check exists solely inside `provision?`, and it is broken for the `prevent_with_label` branch. `Repository#provisioning_behavior_prevent_with_label?` is a plain enum predicate with no awareness of `review_stacks_enabled`. [4](#0-3) 

The attacker's exact action: open a PR against a GitHub repository connected to Shipit whose configuration is `review_stacks_enabled: false`, `provisioning_behavior: prevent_with_label`, with no labels applied — a normal, unprivileged PR-opening action requiring no Shipit credentials, only a legitimate GitHub webhook delivery (which is signature-verified upstream but not spoofed; the attacker simply performs the real GitHub action of opening a PR with no labels).

### Impact Explanation
A `ReviewStack` row and its associated `PullRequest`, `Stack` provisioning-queue entry, branch/environment (`pr#{number}`) get created and queued for a repository that explicitly opted out of review-stack provisioning (`review_stacks_enabled: false`). This causes unauthorized resource creation and downstream provisioning workflow execution (deploy scripts, environment setup, etc. via `Shipit::ReviewStackProvisioningQueue.add`/provisioning handlers) for a repository/team that disabled the feature, matching the "unauthorized deploy" / "record written that shouldn't have been" category. It is repeatable for any repository configured this way and requires no elevated privileges — just opening an unlabeled PR.

### Likelihood Explanation
Requires the repository owner/operator to have configured `review_stacks_enabled: false` together with `provisioning_behavior: prevent_with_label` — a plausible, even common, configuration for teams that want label-gated review-stacks or none at all. Attacker cost is trivial: open a PR with no labels (default state for any new PR). No secrets, sessions, or special access needed beyond ordinary GitHub PR-opening ability on a repo already connected to Shipit. Fully repeatable.

### Recommendation
Add explicit parentheses/grouping so `review_stacks_enabled` gates all three branches, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` style, using existing fixtures):
1. Set up a `Repository` fixture/record with `review_stacks_enabled: false`, `provisioning_behavior: 'prevent_with_label'`.
2. Build `params` for an `opened` pull_request webhook payload with `pull_request.labels: []` (no labels) referencing that repository's `full_name`.
3. Before invoking: assert `repository.review_stacks_enabled == false` and compute `handler.send(:provision?)` — expect it to equal `repository.review_stacks_enabled` (i.e., `false`) per the intended binding.
4. Invoke `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(params).process`.
5. Assert `Shipit::ReviewStack.where(environment: "pr#{params.number}").exists?` — with the bug, this is `true`, violating the binding from step 3 (`provision?` returned `true` while `review_stacks_enabled` is `false`).

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

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
```
