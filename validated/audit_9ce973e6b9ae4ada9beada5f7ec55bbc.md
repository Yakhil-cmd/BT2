### Title
`review_stacks_enabled` is not enforced for `prevent_with_label`/`allow_with_label` due to operator precedence bug in `provision?` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
The `provision?` method in `OpenedHandler` uses Ruby's `&&`/`||` operator precedence in a way that only gates the `provisioning_behavior_allow_all?` clause with `repository.review_stacks_enabled`, leaving `provisioning_behavior_allow_with_label?` and `provisioning_behavior_prevent_with_label?` completely unconstrained by that flag. The Settings UI documents `review_stacks_enabled` as the master toggle ("Dynamically provision stacks for Pull Requests?"), so any repository configured with `prevent_with_label` behavior will still auto-provision review stacks for unlabeled PRs even when the operator has disabled review stacks entirely.

### Finding Description
The intended binding is: `review_stacks_enabled == true` must be a strict precondition for stack provisioning under any `provisioning_behavior`, as documented in `app/views/shipit/repositories/settings.html.erb:12-13` ("Dynamically provision stacks for Pull Requests?").

The actual code in `provision?` is:
```ruby
repository.review_stacks_enabled &&
  repository.provisioning_behavior_allow_all? ||
  (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
  (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
``` [1](#0-0) 

Due to Ruby's `&&` binding tighter than `||`, this parses as:
```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)
```
So `review_stacks_enabled` is ANDed only into the first disjunct. The second and third disjuncts (`allow_with_label?` and `prevent_with_label?` branches) are evaluated independently of `review_stacks_enabled`.

Exploit path: An attacker (unprivileged, PR author on any repo whose operator uses `prevent_with_label` with `review_stacks_enabled = false`, intending to fully disable review stacks except perhaps for manual override) opens a PR with zero labels. GitHub sends the `pull_request opened` webhook, which reaches `OpenedHandler#process` → `respond_to_pull_request_opened?` → `provision?`. Since `repository.provisioning_behavior_prevent_with_label?` is true and `pull_request_has_provisioning_label?` is false, the third disjunct evaluates to `true`, making `provision?` return `true` regardless of `review_stacks_enabled`. This triggers `ReviewStackAdapter#find_or_create!` [2](#0-1)  which provisions a real `Stack`/`ReviewStack`, eventually running deploy-host commands for that branch.

None of the existing guards prevent this: `verify_signature`/webhook signature checks only authenticate that GitHub sent the payload, not the payload's semantic legitimacy; there is no separate check enforcing `review_stacks_enabled` before calling `provision?`; and the existing test suite does not cover the case of `prevent_with_label` combined with `review_stacks_enabled: false` — the closest test, `"create stacks for repos what prevent_with_label when label is absent"` [3](#0-2) , uses `configure_provisioning_behavior` with its default `provisioning_enabled: true` [4](#0-3) , so it never exercises the disabled-flag scenario and the divergence is untested. The same precedence bug is duplicated in `ReopenedHandler#unarchive?` [5](#0-4) .

### Impact Explanation
For any repository configured with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false` — a configuration the UI presents as "review stacks disabled" — an unprivileged PR author can force creation of a `ReviewStack`/`Stack` and drive it into `awaiting_provision?`, leading to deploy-host command execution for that repository's provisioning/deploy tasks. This is a cross-repository-setting bypass: the operator's explicit "review stacks off" toggle is silently ignored for one of the three behavior modes. It matches "an unauthorized deploy... a record written for a repository that did not authenticate it" and RCE-via-provisioning severity for repositories using this combination. The attack is repeatable for every PR against any repository sharing this configuration; blast radius is confined to repositories that use `prevent_with_label`, but for those it is a complete authorization-toggle bypass.

### Likelihood Explanation
Preconditions: the target repository must have `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false` set by its operator (a plausible, UI-supported configuration intended to fully disable auto-provisioning while still allowing a `provisioning_label_name` opt-out mechanic conceptually, or simply an operator who toggled `review_stacks_enabled` off believing it's a master kill switch). No Shipit secrets, sessions, or elevated permissions are required — only opening a PR with no labels, which is fully within attacker capability. This is trivially exploitable and 100% reproducible on any matching repository.

### Recommendation
Fix the operator precedence bug by scoping `review_stacks_enabled` across all three disjuncts, e.g.:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Apply the identical fix to `ReopenedHandler#unarchive?`.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, add:
```ruby
test "does not create stacks for repos with review_stacks disabled even under prevent_with_label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false, # review_stacks_enabled = false
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  # Binding under test: review_stacks_enabled == false must imply provision? == false
  handler = OpenedHandler.new(payload)
  assert_equal false, repository.reload.review_stacks_enabled
  assert_no_difference -> { Shipit::Stack.count } do
    handler.process
  end
end
```
With the current code, `Shipit::Stack.count` changes (provisioning occurs) despite `review_stacks_enabled == false`, proving the bypass; after the recommended fix, no stack is created.

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

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L189-196)
```ruby
          def configure_provisioning_behavior(repository:, provisioning_enabled: true, behavior: :allow_all, label: nil)
            repository.review_stacks_enabled = provisioning_enabled
            repository.provisioning_behavior = behavior
            repository.provisioning_label_name = label
            repository.save!

            repository
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
