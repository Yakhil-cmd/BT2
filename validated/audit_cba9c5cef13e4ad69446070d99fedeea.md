### Title
`review_stacks_enabled` fails to gate `allow_with_label`/`prevent_with_label` provisioning due to `&&`/`||` precedence, allowing PR reopen to re-provision stacks even when review stacks are disabled - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`PullRequest::ReopenedHandler#unarchive?` writes the gating condition as `repository.review_stacks_enabled && allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. Because Ruby's `&&` binds tighter than `||`, `review_stacks_enabled` only scopes the first `allow_all?` disjunct, not the `allow_with_label?`/`prevent_with_label?` disjuncts. The existing test suite has no case exercising `review_stacks_enabled: false` combined with `allow_with_label` and a matching label, so this divergence between intended and actual behavior is untested and undetected.

### Finding Description
The intended binding is: `unarchive? == true` **iff** `review_stacks_enabled == true` **AND** one of (`allow_all?`, `allow_with_label? && has_label?`, `prevent_with_label? && !has_label?`) holds. The actual code at [1](#0-0)  evaluates as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)` per Ruby operator precedence rules (`&&` binds tighter than `||`). Consequently, if `review_stacks_enabled == false` but `provisioning_behavior == allow_with_label` and the reopened PR carries the matching label, `unarchive?` returns `true`, and `process` at [2](#0-1)  calls `stack.unarchive!`, which (via `ReviewStackAdapter#unarchive!`) re-queues the stack for provisioning at [3](#0-2) . The same precedence bug exists in `OpenedHandler#provision?` at [4](#0-3) , so a brand-new stack can also be created and provisioned. Provisioning executes deploy/provisioning tasks (`Command`/`PTY.spawn`), so this results in command execution that the `review_stacks_enabled` toggle was meant to prevent.

The test file `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb` never calls `configure_provisioning_behavior` with `provisioning_enabled: false`; every test in that file uses the default `provisioning_enabled: true` [5](#0-4) , and the `allow_with_label` matching-label test at lines 92-107 only asserts behavior with `review_stacks_enabled` left at its default `true` [6](#0-5) . No existing assertion checks `review_stacks_enabled: false` + `allow_with_label` + matching label, so the precedence bug is unverified for the reopen path.

None of the standard guards intercept this: `params` schema validation only validates payload shape, not business logic [7](#0-6) ; `drop_unhandled_event`/signature verification only gate whether the webhook handler runs at all, not the `unarchive?` predicate itself.

### Impact Explanation
For the specific repository whose Shipit `Repository` record has `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label`, an attacker who owns/controls that GitHub repository (or can label a PR against it) can reopen a PR carrying the provisioning label and force Shipit to unarchive/provision (or, via `OpenedHandler`, freshly create and provision) a review stack, running deploy/provisioning `Command`s on the Shipit host — despite the operator having explicitly disabled review stacks for that repository. This is a same-repository re-provisioning bypass of an intended master off-switch, not a cross-tenant bypass (the blast radius is scoped to repositories where this specific misconfigured-looking-but-legal combination exists), matching the "unauthorized deploy/re-provisioning" Critical category when provisioning tasks execute arbitrary commands.

### Likelihood Explanation
Exploitability requires a specific server-side configuration: a `Repository` with `review_stacks_enabled: false` AND `provisioning_behavior: allow_with_label` (or `prevent_with_label`) already set by whoever administers that Stack in Shipit. Given that configuration exists, the "attack" is trivial and cheap: open/reopen a PR and apply the configured label — no secrets, tokens, or elevated GitHub/Shipit permissions needed beyond what's already available to any contributor able to label PRs on that repo. It is repeatable for any repository configured this way.

### Recommendation
Parenthesize the boolean expression so `review_stacks_enabled` gates all three provisioning-behavior branches, e.g.:
```ruby
def unarchive?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the identical fix to `OpenedHandler#provision?`.

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`:
```ruby
test "does not unarchive stacks when review_stacks_enabled is false, even with allow_with_label matching label" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process

  assert stack.reload.archived?, "Expected stack to remain archived because review_stacks_enabled is false"
end
```
With the current code, `repository.review_stacks_enabled == false` and `repository.provisioning_behavior_allow_with_label? == true` and `pull_request_has_provisioning_label? == true`, yet `unarchive?` evaluates to `true` (because `review_stacks_enabled` only gates the `allow_all?` branch), so the assertion `stack.reload.archived?` fails — proving the binding `review_stacks_enabled == true` is not actually enforced for the `allow_with_label` branch.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
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
