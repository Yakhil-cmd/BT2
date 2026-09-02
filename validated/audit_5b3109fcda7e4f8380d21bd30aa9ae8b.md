### Title
`review_stacks_enabled` gate bypassed by `&&`/`||` operator-precedence bug in `provision?`/`unarchive?` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb, app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`OpenedHandler#provision?` and `ReopenedHandler#unarchive?` intend to gate all review-stack provisioning behind `repository.review_stacks_enabled`, but because `&&` binds tighter than `||` in Ruby, the `review_stacks_enabled` check is only ANDed into the `allow_all` branch. For `allow_with_label` and `prevent_with_label` repositories, provisioning/unarchiving proceeds even when `review_stacks_enabled` is `false`. An attacker who fully controls their own pull request (open/close/reopen, plus labeling of their own PR as permitted by this audit's threat model) can trigger `ReviewStackAdapter#create!`/`#unarchive!` on a repository that has explicitly disabled review stacks.

### Finding Description
The intended binding is: `repository.review_stacks_enabled == false` ⇒ `provision?/unarchive? == false`, for every value of `provisioning_behavior`.

Actual code in both handlers: [1](#0-0) [2](#0-1) 

```ruby
def provision?/unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` has higher precedence than `||`, this parses as:

```ruby
(repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?) ||
  (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
  (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```

With `review_stacks_enabled = false`, `provisioning_behavior = :allow_with_label`, and the provisioning label present on the PR:
- Term 1: `false && true` = `false`
- Term 2: `true && true` = `true`
- Result: `true`

So `provision?`/`unarchive?` returns `true` even though `review_stacks_enabled` is `false`. Both `OpenedHandler#process` and `ReopenedHandler#process` then unconditionally call into `Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter#find_or_create!`/`#unarchive!`, which create/unarchive the `ReviewStack`, enqueue it via `Shipit::ReviewStackProvisioningQueue.add`, and eventually trigger the `deprovisioned -> provisioning` transition that calls `stack.provisioner.up`. [3](#0-2) [4](#0-3) [5](#0-4) 

The attacker's exact request: open (or close+reopen) a pull request against a repository configured with `review_stacks_enabled=false`, `provisioning_behavior=allow_with_label`, `provisioning_label_name` set, and attach that label to their own PR — all actions this audit's threat model attributes to an unprivileged PR author. GitHub signs and delivers the resulting `pull_request` webhook normally; `verify_signature`/`ExplicitParameters` correctly validate the payload shape and signature, but neither checks the internal provisioning-gate business logic, so they do not catch this divergence. None of `force_github_authentication`, `User#authorized?`, `require_permission!`, or model validations are involved in this decision path at all — the bug is purely in the boolean expression.

### Impact Explanation
The maintainer's explicit choice to disable review-stack provisioning (`review_stacks_enabled=false`) is bypassed for any repository configured with `allow_with_label`/`prevent_with_label`. This causes: (a) an unauthorized `Shipit::ReviewStack` record to be created/unarchived for a repository configuration that forbids it, (b) enqueuing into `Shipit::ReviewStackProvisioningQueue`, and (c) eventual execution of the repository's registered `ProvisioningHandler#up` (which, per `docs/review_stacks.md`, host applications implement to allocate real infrastructure/commands) — this is unauthorized task execution triggered purely by the PR author cycling open/close/reopen and labeling their own PR. It is repeatable at will against any repository using this configuration; blast radius is scoped to repositories using `allow_with_label`/`prevent_with_label` with `review_stacks_enabled=false`, but is fully attacker-controlled and repeatable without any privileged credentials.

### Likelihood Explanation
Preconditions: a repository must have `review_stacks_enabled=false` combined with `provisioning_behavior=allow_with_label` (with label present) or `prevent_with_label` (with label absent) — a plausible/likely misconfiguration for an operator who wants review stacks entirely off. No secrets or elevated privileges are needed; the attacker only needs to open/reopen/close a PR and control its labels, which is within their own PR lifecycle. This is highly feasible and trivially repeatable.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates every branch:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Apply the same fix to `ReopenedHandler#unarchive?`.

### Proof of Concept
minitest in `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb` style:
```ruby
test "does NOT unarchive when review_stacks_enabled is false, even for allow_with_label with label present" do
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

  # Expected binding: review_stacks_enabled == false => archived? stays true, awaiting_provision? stays false
  assert stack.reload.archived?, "Expected stack to remain archived because review_stacks_enabled is false"
  assert_not stack.awaiting_provision?, "Expected stack NOT to be queued for provisioning"
end
```
Running this against current code fails: `stack.reload.archived?` is `false` and `awaiting_provision?` is `true`, confirming the bypass. An analogous test against `OpenedHandler#provision?` demonstrates the same bug for PR creation.

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

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
      end
```
