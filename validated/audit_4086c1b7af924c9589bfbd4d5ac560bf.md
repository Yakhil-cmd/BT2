### Title
`ReopenedHandler#unarchive?` allows PR review-stack provisioning while `review_stacks_enabled` is `false` due to `&&`/`||` operator precedence - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler#unarchive?` and `OpenedHandler#provision?` both write `repository.review_stacks_enabled && provisioning_behavior_allow_all? || (...) || (...)`, which Ruby parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. This means `review_stacks_enabled` only gates the `allow_all` branch, not the `allow_with_label`/`prevent_with_label` branches, unlike `LabeledHandler#respond_to_label_change?` and `UnlabeledHandler#respond_to_label_change?`, which correctly `AND` `repository.review_stacks_enabled` against the outer disjunction `(archive? || unarchive?)`.

### Finding Description
The intended binding is: `repository.review_stacks_enabled == true` must be a necessary condition for any provisioning action (`unarchive!`/`find_or_create!`) regardless of `provisioning_behavior`. That binding holds in `LabeledHandler`: [1](#0-0) 

and `UnlabeledHandler`: [2](#0-1) 

both of which place `repository.review_stacks_enabled` as a standalone conjunct ANDed against the entire `(archive? || unarchive?)` disjunction.

`ReopenedHandler#unarchive?` instead inlines `review_stacks_enabled` into the first disjunct only: [3](#0-2) 

Because `&&` has higher precedence than `||` in Ruby, this evaluates as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. When `review_stacks_enabled` is `false`, `provisioning_behavior_allow_with_label?` is `true`, and the PR carries the provisioning label, `unarchive?` still returns `true`. `respond_to_pull_request_reopened?` then returns `true` and `process` calls `stack.unarchive!`, which (via `ReviewStackAdapter#unarchive!`) either un-archives an existing archived `ReviewStack` or creates a brand-new one via `find_or_create!`-equivalent `create!` path: [4](#0-3) [5](#0-4) 

`OpenedHandler#provision?` has the identical precedence bug: [6](#0-5) 

Attack path: A repository has `review_stacks_enabled: false` (operator intentionally disabled review-stack provisioning) but retains a leftover `provisioning_behavior: allow_with_label` configuration and provisioning label. An unprivileged actor who can open/close/reopen a PR on that repository and cause the provisioning label to be present sends a `pull_request` webhook with `action: "reopened"`. `ReopenedHandler` unarchives/creates the `ReviewStack` and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` despite review stacks being disabled for the repo — while the same repository configuration correctly blocks `labeled`/`unlabeled` events from doing the same thing.

Existing guards don't stop this: signature verification (`verify_signature`) only authenticates that the payload came from GitHub for that repo/installation, it does not enforce the `review_stacks_enabled` business rule; `drop_unhandled_event` and `ExplicitParameters` only validate the shape of the payload, not the gating logic; there is no separate authorization check on `provisioning_behavior` vs. `review_stacks_enabled`.

### Impact Explanation
The effect is that operator intent (`review_stacks_enabled = false`) is bypassed for the `reopened` (and `opened`) lifecycle event on a repository the operator explicitly disabled review-stack provisioning for. This causes the engine to unarchive/create a `ReviewStack` record, enqueue it into `ReviewStackProvisioningQueue`, and set up provisioning tasks/deploys for a stack that should not exist — an unauthorized provisioning/deploy action performed against the operator's configuration. It is scoped to the repository whose configuration has this specific combination (`review_stacks_enabled: false` + `provisioning_behavior: allow_with_label`/`prevent_with_label`); it does not cross repository/tenant boundaries. This matches the "unauthorized deploy" category under Critical, restricted to same-repository blast radius.

### Likelihood Explanation
Requires a specific, plausible-but-narrow misconfiguration: `review_stacks_enabled: false` while `provisioning_behavior` remains `allow_with_label` or `prevent_with_label` (e.g., an operator disabling review stacks without resetting the behavior field, or re-enabling later). Given that combination exists, exploitation only requires the ability to trigger a `reopened` PR webhook with (or without, for `prevent_with_label`) the provisioning label — actions available to anyone who can open/close/reopen PRs and influence labels on the target repository. It is deterministic and repeatable against any repository sharing this configuration state.

### Recommendation
Add explicit parentheses (or refactor to match `LabeledHandler`'s pattern) so `review_stacks_enabled` gates the entire disjunction in both `ReopenedHandler#unarchive?` and `OpenedHandler#provision?`:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to `OpenedHandler#provision?`.

### Proof of Concept
minitest plan (mirrors existing fixtures/helpers in `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`):
1. Create an archived `ReviewStack` for `shipit_repositories(:shipit)` (`create_archived_stack`).
2. Configure the repository: `review_stacks_enabled = false`, `provisioning_behavior = :allow_with_label`, `provisioning_label_name = "pull-requests-label"`.
3. Build `payload_parsed(:pull_request_reopened)` and add the label `"pull-requests-label"` to `payload["pull_request"]["labels"]`.
4. Assert on `LabeledHandler` side (correct gating): run `LabeledHandler.new(payload.merge(action: "labeled")).process` and assert `stack.reload.archived?` is still `true` (blocked, since `review_stacks_enabled` is `false`).
5. Assert on `ReopenedHandler` side (bug): run `ReopenedHandler.new(payload).process` on the *same* stack/repository state and assert `stack.reload.archived?` is `false` and `stack.awaiting_provision?`/enqueued in `Shipit::ReviewStackProvisioningQueue` — demonstrating the divergence between the two handlers under identical `review_stacks_enabled: false` configuration. [7](#0-6) [8](#0-7)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb (L92-107)
```ruby
          test "unarchives stacks for repos that allow_with_label when label is present" do
            stack = create_archived_stack
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :allow_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_reopened)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process

            assert_not stack.reload.archived?, "Expected stack to be NOT be archived"
            assert_pending_provision(stack)
          end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb (L200-207)
```ruby
          def configure_provisioning_behavior(repository:, provisioning_enabled: true, behavior: :allow_all, label: nil)
            repository.review_stacks_enabled = provisioning_enabled
            repository.provisioning_behavior = behavior
            repository.provisioning_label_name = label
            repository.save!

            repository
          end
```
