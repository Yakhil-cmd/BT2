### Title
`unarchive?` disjunct 3 ignores `review_stacks_enabled`, allowing re-provisioning of archived review stacks when review stacks are disabled - (File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb)

### Summary
`ReopenedHandler#unarchive?` combines four boolean terms with mixed `&&`/`||` without parenthesizing the leading `review_stacks_enabled` guard across all three provisioning-behavior branches, so Ruby operator precedence (`&&` binds tighter than `||`) only applies the `review_stacks_enabled` gate to the `allow_all?` branch. When `provisioning_behavior_prevent_with_label?` is true and the PR simply lacks the label, disjunct 3 evaluates to `true` regardless of `review_stacks_enabled`, causing `stack.unarchive!` to run and `Shipit::ReviewStackProvisioningQueue.add` to enqueue re-provisioning even though review stacks are disabled for that repository.

### Finding Description
The claimed binding is: `review_stacks_enabled == true` must be required for **every** disjunct of `unarchive?`, i.e. `unarchive? == review_stacks_enabled && (allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?))`.

The actual code is:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Due to Ruby precedence, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. The `review_stacks_enabled` check is scoped only to the first term. Setting `review_stacks_enabled = false` and `provisioning_behavior = :prevent_with_label` with an empty `labels` array on the incoming PR makes disjunct 3 evaluate `true`, so `unarchive?` returns `true` regardless of the disabled flag.

`process` then calls `stack.unarchive!` unconditionally when `respond_to_pull_request_reopened?` is true:
```ruby
def process
  return unless respond_to_pull_request_reopened?
  stack.unarchive!
end
``` [2](#0-1) 

`stack` is a `ReviewStackAdapter` scoped to `repository.review_stacks`, and `unarchive!` either re-provisions an existing archived stack or creates a new one, and in both paths it calls `Shipit::ReviewStackProvisioningQueue.add`:
```ruby
def unarchive!(*args, &block)
  if stack.blank?
    ...
    return create!
  end
  return unless stack.archived?

  stack.transaction do
    Shipit::ReviewStackProvisioningQueue.add(stack)
    stack.unarchive!(*args, &block)
  end
end
``` [3](#0-2) 
(`create!` also calls `Shipit::ReviewStackProvisioningQueue.add(stack)` at line 82.) [4](#0-3) 

This is reachable via the public webhook endpoint: the attacker opens a PR against the tracked repo (fork PR), the repo's owner/admin has configured `provisioning_behavior_prevent_with_label`, but has left `review_stacks_enabled = false` (i.e., intending review-stack provisioning to be off entirely). The attacker simply omits the "prevent" label from their PR (the default state - most PRs won't carry the label), then closes/reopens the PR (or the "reopened" webhook event fires). This sends a standard, validly-signed `pull_request` `reopened` webhook (GitHub itself signs it with `webhook_secret`, which the attacker does not need to know) through `WebhooksController#create` → `verify_signature` (which passes because it's a legitimate GitHub-originated webhook) → `ReopenedHandler.call`. Signature verification, `drop_unhandled_event`, and the `ExplicitParameters` schema all check payload authenticity/shape but do not touch the `review_stacks_enabled`/`provisioning_behavior` gating logic, so they do not prevent this divergence.

Existing tests demonstrate the analogous (intended) `prevent_with_label` behavior only when `review_stacks_enabled` is true (via `configure_provisioning_behavior` which always sets it to `true`) [5](#0-4) [6](#0-5)  — there is no test in the suite covering `review_stacks_enabled: false` combined with `prevent_with_label`, confirming this branch is untested and the precedence bug is unnoticed.

The identical operator-precedence bug is also present in `OpenedHandler#provision?` [7](#0-6) , meaning `opened` events are equally affected, but the question is scoped to `ReopenedHandler`.

### Impact Explanation
When triggered, `Shipit::ReviewStackProvisioningQueue.add(stack)` enqueues the stack for automated provisioning, and `stack.unarchive!` transitions an archived (deprovisioned) review stack back to active, which downstream cron/worker jobs pick up to run provisioning tasks (which execute deploy commands via `Command`/`PTY.spawn` against the repository's provisioning scripts). This is an unauthorized re-provisioning/deploy triggered on a repository whose owner explicitly disabled review stacks (`review_stacks_enabled = false`), initiated entirely by an unprivileged PR author/fork owner. This matches the "Critical" impact category: an unauthorized deploy/provisioning is executed for a repository configuration that should have blocked it. The attack is repeatable against any tracked repository with this specific misconfiguration (`review_stacks_enabled: false`, `provisioning_behavior: prevent_with_label`) by any PR author on that repo, each time they open/reopen a PR without the label.

### Likelihood Explanation
Requires a specific repository configuration: `review_stacks_enabled = false` AND `provisioning_behavior = :prevent_with_label`. This is a plausible real configuration (an admin disabling review stacks globally while retaining a previously configured "prevent with label" policy for when it's re-enabled), but it is a non-default combination that must exist on the target repository. Given that configuration, the attacker's cost is trivial: open/reopen a PR without a specific label, no secrets or elevated access needed, fully repeatable.

### Recommendation
Parenthesize the `review_stacks_enabled` check so it gates all three disjuncts, e.g.:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to `OpenedHandler#provision?`, which has the identical precedence flaw.

### Proof of Concept
Minitest in `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb` style:
```ruby
test "does NOT unarchive/provision when review_stacks_enabled is false, even with prevent_with_label and missing label" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] = []

  Shipit::ReviewStackProvisioningQueue.expects(:add).never

  Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process

  assert stack.reload.archived?, "Expected stack to remain archived because review_stacks_enabled is false"
end
```
Before the fix: `Shipit::ReviewStackProvisioningQueue.add` is invoked and `stack.reload.archived?` is `false`, failing the assertion — confirming the vulnerability. After applying the recommended fix (wrapping the `review_stacks_enabled &&` around the full `||` chain), the mock expectation `.never` holds and the stack remains archived.

### Citations

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

**File:** test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb (L146-161)
```ruby
          test "unarchives stacks for repos that prevent_with_label when label is absent" do
            stack = create_archived_stack
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_reopened)
            payload["pull_request"]["labels"] = []

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
