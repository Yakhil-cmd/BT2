Confirmed: due to Ruby operator precedence, `provision?` in `OpenedHandler` never gates the `allow_with_label` or `prevent_with_label` branches on `review_stacks_enabled`.### Title
`provision?` operator-precedence bug allows Review Stack creation when `review_stacks_enabled == false` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` uses `&&`/`||` in a way that, due to Ruby operator precedence, only gates the `allow_all` branch on `repository.review_stacks_enabled`. The `allow_with_label` and `prevent_with_label` branches are evaluated independently of `review_stacks_enabled`, so a repository with review stacks disabled can still have a `Stack` auto-created from a forged `opened` webhook if its `provisioning_behavior` happens to be `allow_with_label` (label present) or `prevent_with_label` (label absent).

### Finding Description
The intended authorization binding is: `Stack.count` changes via `OpenedHandler#process` **only if** `repository.review_stacks_enabled == true`. In code: [1](#0-0) 
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
In Ruby, `&&` binds tighter than `||`, so this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && label_present) || (prevent_with_label? && !label_present)`

Thus `review_stacks_enabled` is ANDed only with the first disjunct. The second and third disjuncts (`allow_with_label` and `prevent_with_label`) are fully independent of `review_stacks_enabled`. This breaks the equality `provision? == false` whenever `review_stacks_enabled == false` for two of the three `provisioning_behavior` values combined with the corresponding label state:

- `provisioning_behavior = allow_with_label`, label present → `provision?` is `true` even though `review_stacks_enabled = false`.
- `provisioning_behavior = prevent_with_label`, label absent → `provision?` is `true` even though `review_stacks_enabled = false`.

Attack: an unprivileged GitHub user opens a pull request against a repository configured this way (label present for `allow_with_label`, or simply no label for `prevent_with_label`, both attacker-controlled), and the resulting `opened` webhook is delivered to `POST /webhooks`. `OpenedHandler#process` calls `respond_to_pull_request_opened?` → `provision?` → true → `Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter#find_or_create!` → `create!`, which does `scope.create!(stack_attributes)` with `branch: params.pull_request.head.ref` (attacker-controlled) and queues provisioning via `Shipit::ReviewStackProvisioningQueue.add(stack)`: [2](#0-1) 

This is a real authorization bypass: the repository owner explicitly disabled review-stack auto-provisioning (`review_stacks_enabled = false`), yet a Stack is still created and queued for provisioning, eventually leading to execution of the attacker's `shipit.yml` (`Command#start`/`PTY.spawn`) during provisioning — matching the Critical impact category (unauthorized deploy/command execution not authorized by the repository's own configuration).

No other guard intervenes: `respond_to_pull_request_opened?` only checks `params.action == "opened" && provision?`; there is no separate check on `review_stacks_enabled` elsewhere in the call path, and `ExplicitParameters` only validates payload shape, not authorization.

The exact same buggy precedence pattern is duplicated in `ReopenedHandler#unarchive?`: [3](#0-2) 
so the same bypass applies to unarchiving/reprovisioning existing stacks via the `reopened` webhook.

Existing repo tests only exercise the case `review_stacks_enabled: true` (default in `configure_provisioning_behavior`), so the disabled-with-`allow_with_label`/`prevent_with_label` combinations are untested and the bug is not caught: [4](#0-3) 

### Impact Explanation
An attacker who can open a pull request (or forge equivalent webhook payload data, since no signature/authorization boundary is broken here beyond the webhook delivery itself) can force creation of a `Shipit::Stack` record and queue it for provisioning even though the repository owner disabled review-stack auto-provisioning. Provisioning eventually runs the attacker-controlled `shipit.yml` via `Command`, i.e., unauthorized deploy/command execution on the deploy host — Critical. This is repeatable against any repository configured with `provisioning_behavior = allow_with_label` (attacker adds label to own PR) or `provisioning_behavior = prevent_with_label` (attacker simply omits label, which is the default state) while `review_stacks_enabled = false`.

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled = false` and `provisioning_behavior` set to either `allow_with_label` or `prevent_with_label` (not `allow_all`). This is an ordinary, plausible configuration (e.g., an operator disables review stacks but had previously configured a behavior mode, or leaves stale config). No secrets, sessions, or special privileges are required — the attacker only needs to open a PR (and possibly self-apply a label they control) and have the webhook delivered. Cost is trivial and fully repeatable.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the entire expression:
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
Add to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, table-driven over the 6 disabled combinations:
```ruby
[
  [:allow_all, false],
  [:allow_all, true],
  [:allow_with_label, false],
  [:allow_with_label, true],
  [:prevent_with_label, false],
  [:prevent_with_label, true],
].each do |behavior, label_present|
  test "does not create stacks when review_stacks_enabled=false, behavior=#{behavior}, label_present=#{label_present}" do
    repository = shipit_repositories(:shipit)
    configure_provisioning_behavior(
      repository:,
      provisioning_enabled: false,
      behavior: behavior,
      label: "pull-requests-label"
    )
    payload = payload_parsed(:pull_request_opened)
    payload["pull_request"]["labels"] = label_present ? [{ "name" => "pull-requests-label" }] : []

    assert_no_difference -> { Shipit::Stack.count } do
      OpenedHandler.new(payload).process
    end
  end
end
```
Expected: fails for `(allow_with_label, true)` and `(prevent_with_label, false)`, proving `Stack.count` changes despite `review_stacks_enabled == false`, confirming the binding `provision? => review_stacks_enabled == true` is violated in exactly those two combinations.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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
