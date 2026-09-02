This confirms the vulnerability. `ReopenedHandler#unarchive?` is byte-for-byte the same broken boolean expression as `OpenedHandler#provision?`, and it drives `stack.unarchive!` which re-enters the provisioning queue.### Title
`ReopenedHandler#unarchive?` shares `OpenedHandler#provision?`'s operator-precedence flaw, letting `review_stacks_enabled=false` repos with `prevent_with_label` re-trigger provisioning via close→reopen - (File: `app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb`)

### Summary
`ReopenedHandler#unarchive?` uses the exact same boolean expression as `OpenedHandler#provision?`, where Ruby's `&&`/`||` precedence causes `repository.review_stacks_enabled` to only gate the `allow_all?` branch, not the `allow_with_label?`/`prevent_with_label?` branches. On a repository with `review_stacks_enabled=false` and `provisioning_behavior=:prevent_with_label`, reopening a PR without the provisioning label satisfies the `prevent_with_label?` clause unconditionally and calls `stack.unarchive!`, re-enqueuing provisioning.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == true` should be a necessary condition for any of `unarchive?`'s three disjuncts to evaluate `true`. In the actual code:

```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Ruby parses `&&` with higher precedence than `||`, so this is actually:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`.

`review_stacks_enabled` is ANDed only into the first disjunct; the second and third disjuncts (label-based behaviors) are entirely independent of `review_stacks_enabled`. This is the identical defect present in `OpenedHandler#provision?`: [2](#0-1) 

Attack flow: attacker opens a PR against a `review_stacks_enabled=false`, `provisioning_behavior=:prevent_with_label` repository (or one is later closed/archived), never applying the provisioning label. `process` calls `respond_to_pull_request_reopened?` → `unarchive?`: [3](#0-2) 
Since `provisioning_behavior_prevent_with_label?` is `true` and `!pull_request_has_provisioning_label?` is `true` (no label), the third disjunct is `true` regardless of `review_stacks_enabled`, so `unarchive?` returns `true` and `stack.unarchive!` runs, which re-adds the stack to `Shipit::ReviewStackProvisioningQueue` and unarchives it: [4](#0-3) 

No other guard intercepts this: `drop_unhandled_event`/signature verification only authenticate that the payload came from GitHub for *some* repo, not that provisioning is enabled for *this* repo; `Repository.from_github_repo_name` resolution and `ExplicitParameters` schema validation do not check `review_stacks_enabled` either.

### Impact Explanation
On any repository with `review_stacks_enabled=false`, an attacker who can open/close/reopen PRs (i.e., any contributor to their own fork, or if the repo accepts external PRs) can force `stack.unarchive!`, re-enqueuing the previously-provisioned review stack for provisioning of the attacker-controlled branch — even though the operator explicitly disabled review stacks and configured `prevent_with_label` to require opt-in via label. This re-triggers the review-stack provisioning pipeline (a documented RCE-capable code path in this engine), so the impact matches Critical: unauthorized triggering of provisioning/deploy-like behavior for a repository/branch the operator did not authorize. This affects any repository so misconfigured/opted-out, not just one specific tenant, but is scoped per-repository (does not cross into other repos' stacks).

### Likelihood Explanation
Preconditions: repository must have `review_stacks_enabled=false` and `provisioning_behavior=:prevent_with_label`, and must have (or previously had) an archived review stack for the PR's `pr#{number}` environment (created while stacks were possibly enabled, or via the same-class bug in `LabeledHandler`/`OpenedHandler`). Attacker cost is minimal: open a PR, close it, reopen it (all standard GitHub actions requiring no privileged token), with no provisioning label. This is fully repeatable against any repo in this misconfigured state.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the entire expression:
```ruby
def unarchive?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the same fix to `OpenedHandler#provision?`.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb` (existing suite):
1. Create a repository with `review_stacks_enabled: false, provisioning_behavior: :prevent_with_label`.
2. Create an archived `Shipit::ReviewStack` for `environment: "pr<number>"` under that repository.
3. Build a `pull_request_reopened` payload for that PR/number with no labels (`pull_request.labels: []`).
4. Post the payload through the webhook handler (`ReopenedHandler.new(payload_parsed(:pull_request_reopened)).process` or via the controller route).
5. Assert `stack.reload.archived?` is `false` and that `Shipit::ReviewStackProvisioningQueue` contains the stack (`awaiting_provision?` true) — demonstrating `unarchive?` returned `true` despite `review_stacks_enabled == false`, confirming the broken binding.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-68)
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

          def pull_request
            params.pull_request
          end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
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
