### Title
`ReopenedHandler#unarchive?` operator-precedence bug allows unauthorized re-provisioning of review-stack-disabled repositories - (File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb)

### Summary
`ReopenedHandler#unarchive?` contains the same operator-precedence defect as `OpenedHandler#provision?`: `repository.review_stacks_enabled && repository.provisioning_behavior_allow_all? || (...)`. Because `&&` binds tighter than `||` in Ruby, the third clause `(repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)` is evaluated as an independent OR branch and is never gated by `review_stacks_enabled`. Sending a `pull_request` `reopened` webhook for an archived (or even non-existent) stack on a repository with `review_stacks_enabled: false` and `provisioning_behavior: :prevent_with_label` (no label attached) causes `unarchive?` to return true, triggering `ReviewStackAdapter#unarchive!` and `ReviewStackProvisioningQueue.add`.

### Finding Description
Binding claimed: `repository.review_stacks_enabled == false` must gate all provisioning behavior branches before `ReopenedHandler#unarchive?` returns true. The actual code: [1](#0-0) 

evaluates as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)` due to Ruby operator precedence (`&&` > `||`). With `review_stacks_enabled: false`, `provisioning_behavior: :prevent_with_label`, and no provisioning label on the PR, the third disjunct evaluates `true && !false` → `true`, so `unarchive?` returns `true` regardless of `review_stacks_enabled`.

`respond_to_pull_request_reopened?` requires only `params.action == "reopened"` plus this broken `unarchive?` check [2](#0-1) . This passes and calls `stack.unarchive!`, which is `ReviewStackAdapter#unarchive!` [3](#0-2) . That method either calls `create!` (if no stack exists) or, if the stack exists and is archived, calls `ReviewStackProvisioningQueue.add(stack)` then `stack.unarchive!` [4](#0-3) . `ReviewStackProvisioningQueue.add` enqueues the stack for provisioning [5](#0-4) , and the background worker will eventually run the repository's `shipit.yml` provisioning commands (`Command#start`) against the newly pushed branch head.

Existing guards do not stop this: webhook signature verification only authenticates that GitHub sent the payload, not that the repository is authorized for review stacks; `params` schema validation only checks types/shapes, not the `review_stacks_enabled` business rule; there is no additional check downstream in `ReviewStackAdapter` or `ReviewStackProvisioningQueue` that re-verifies `review_stacks_enabled` before enqueuing/provisioning.

This is a distinct but structurally identical vulnerability to the one already presumably fixed/flagged for `OpenedHandler#provision?` — it lives in a separate handler class (`ReopenedHandler`) triggered by a separate webhook `action` value (`reopened`), so it is a separate exploitable code path that must be fixed independently.

### Impact Explanation
An attacker who can open and then close/reopen a pull request against any public repository configured with `review_stacks_enabled: false` and `provisioning_behavior_prevent_with_label` (with no label present) can force Shipit to create/unarchive a review stack and enqueue it for provisioning, ultimately executing the repository's `shipit.yml`-defined provisioning commands via `Command#start` on the Shipit deploy host. Since the attacker controls the PR head branch/commit content (via their own fork), this is equivalent to unauthorized RCE / unauthorized deploy triggered against a repository whose owner explicitly disabled review stacks — matching the "Critical: RCE on the deploy host via `Command`" and "unauthorized deploy" categories. It's repeatable against any repository matching this configuration by any GitHub user able to open/reopen PRs.

### Likelihood Explanation
Preconditions: target repository must have `review_stacks_enabled: false` and `provisioning_behavior: :prevent_with_label`, and the attacker's PR must lack the provisioning label (the default state for an unprivileged attacker's PR, since labels are typically applied by maintainers). No secrets, tokens, or elevated GitHub permissions are required — only the ability to open/close/reopen a PR from a fork, which any GitHub user has. Webhooks are sent automatically by GitHub for these standard PR lifecycle events, so the attacker only needs normal PR interactions, making this highly feasible and repeatable.

### Recommendation
Add explicit parentheses (or refactor into a guard clause) in `ReopenedHandler#unarchive?` so `review_stacks_enabled` gates every branch:
```ruby
def unarchive?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the identical fix to `OpenedHandler#provision?` and any other handler (e.g. `LabeledHandler`, `UnlabeledHandler`) sharing this pattern, and add a shared/tested helper to avoid duplicating the precedence-sensitive logic across handlers.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`, adapting existing fixtures):
1. Create a `Repository` fixture with `review_stacks_enabled: false`, `provisioning_behavior: :prevent_with_label`.
2. Build a `pull_request_reopened` webhook payload (action `"reopened"`) for that repository's PR with `labels: []` (no provisioning label).
3. Expect `Shipit::ReviewStackProvisioningQueue.expects(:add)` (or `create!`/`unarchive!` path) to be called — asserting the binding `repository.review_stacks_enabled == false` should have prevented `ReviewStackAdapter#unarchive!`/`ReviewStackProvisioningQueue.add` from being reached, but currently is not.
4. Run `Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process` and assert the mock expectation is satisfied, demonstrating provisioning is triggered despite `review_stacks_enabled == false`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L65-68)
```ruby
          def respond_to_pull_request_reopened?
            params.action == "reopened" &&
              unarchive?
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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L9-11)
```ruby
    def self.add(stack)
      stack.enqueue_for_provisioning
    end
```
