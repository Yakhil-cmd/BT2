### Title
`OpenedHandler#provision?` operator-precedence bug bypasses `review_stacks_enabled=false` via attacker-controlled PR label - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` uses Ruby's `&&`/`||` precedence incorrectly, so `repository.review_stacks_enabled` only gates the `allow_all` branch, not the `allow_with_label` or `prevent_with_label` branches. An attacker who can label their own PR can trigger review-stack provisioning even when an operator has explicitly set `review_stacks_enabled = false`.

### Finding Description
The claimed authorization binding is: `repository.review_stacks_enabled == true` must hold for any provisioning path to execute. The actual code is: [1](#0-0) 

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` binds tighter than `||` in Ruby, this parses as:

```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)
```

not the intended:

```
review_stacks_enabled && (allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?))
```

So when `repository.review_stacks_enabled == false` and `repository.provisioning_behavior == :allow_with_label`, the first disjunct is `false`, but the second disjunct `(allow_with_label? && pull_request_has_provisioning_label?)` is evaluated independently of `review_stacks_enabled` and can be `true` purely because the attacker included `repository.provisioning_label_name` in their own PR's `labels` array, which is fully attacker-controlled webhook payload data via `pull_request_label_names` ( [2](#0-1) ). The same flaw applies symmetrically to the `prevent_with_label` branch.

`respond_to_pull_request_opened?` gates `process` solely on `provision?`, and `process` immediately calls `ReviewStackAdapter#find_or_create!`, which creates a `ReviewStack` with `branch: params.pull_request.head.ref` (attacker's fork branch) and queues it for provisioning ( [3](#0-2)  and [4](#0-3) ). No further check on `review_stacks_enabled` occurs in `ReviewStackAdapter`.

None of the existing guards prevent this: `params` schema validation only checks types/presence, not label semantics; `NullRepository#review_stacks_enabled` returning `false` doesn't help because a tracked repository with `allow_with_label` behavior is a real `Repository`, not a `NullRepository`; and the existing test suite's negative test for the disabled flag only exercises `behavior: :allow_all` (`"only provision stacks for repos with auto-provisioning enabled"`), never combining `provisioning_enabled: false` with `allow_with_label`/`prevent_with_label`, so the precedence bug is untested and unnoticed ( [5](#0-4) ).

### Impact Explanation
An outside contributor opening a PR against a repository configured with `provisioning_behavior: allow_with_label` (or `prevent_with_label`) can force `Shipit::ReviewStack` creation and queuing for provisioning even though the operator has globally disabled review stacks (`review_stacks_enabled = false`) for that repository. The queued stack eventually runs `shipit.yml`/provisioning steps sourced from the attacker's own branch, leading to execution of attacker-authored deploy/provision steps on the Shipit deploy host — this is Critical: an unauthorized action (provisioning + subsequent command execution) is triggered for a repository configuration that explicitly opted out, by an attacker who fully controls only their own PR's labels and branch content.

### Likelihood Explanation
Preconditions are narrow but realistic: `repository.review_stacks_enabled == false` and `repository.provisioning_behavior` set to `allow_with_label` (or `prevent_with_label`) — a plausible partial-lockdown operator configuration (e.g., temporarily disabling review stacks while leaving the per-PR label policy configured). The attacker needs only to add a label to their own open pull request, something explicitly allowed under an unprivileged contributor role, and open (or reopen) the PR to trigger `OpenedHandler`. This is trivially repeatable for every PR on the affected repository, requiring no secrets or elevated privileges.

### Recommendation
Fix the operator precedence in `provision?` by explicitly parenthesizing the `review_stacks_enabled` gate around the entire disjunction:

```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the identical fix to `ReopenedHandler` if it has the same pattern (it references `review_stacks_enabled` too, per grep results) and audit `LabeledHandler`/`UnlabeledHandler` for the same construct.

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:

```ruby
test "does not create stacks for allow_with_label repos when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```

Binding under test: `repository.review_stacks_enabled == false` should imply `provision? == false` regardless of `provisioning_behavior`/label state. With current code, `provision?` evaluates to `true` (stack created), failing the `assert_no_difference` — demonstrating the bypass. After applying the recommended parenthesization fix, `provision?` correctly evaluates to `false` and the test passes.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L72-78)
```ruby
          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
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

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L96-107)
```ruby
          test "only provision stacks for repos with auto-provisioning enabled" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              provisioning_enabled: false,
              behavior: :allow_all
            )

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload_parsed(:provision_disabled_pull_request)).process
            end
          end
```
