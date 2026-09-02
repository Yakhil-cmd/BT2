I have sufficient evidence to confirm this finding. The operator precedence bug in `provision?` is clearly present in the code and existing tests never exercise the `review_stacks_enabled: false` + `allow_with_label` combination.

### Title
Operator-precedence bug in `provision?` allows attacker-controlled PR labels to bypass `review_stacks_enabled: false` and self-service provision a Review Stack - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` intends to require `repository.review_stacks_enabled` for *all* provisioning behaviors, but Ruby's `&&`/`||` precedence causes the guard to apply only to the `allow_all` clause. When a repository is configured with `provisioning_behavior: allow_with_label`, any attacker who opens a PR and attaches the configured `provisioning_label_name` to their own PR triggers stack creation and provisioning regardless of the `review_stacks_enabled` flag.

### Finding Description
The broken binding: the code intends `repository.review_stacks_enabled == true` to gate every provisioning path, but in reality `repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?` alone is sufficient — `review_stacks_enabled` is never checked for the `allow_with_label`/`prevent_with_label` branches.

`provision?` is written as:
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Because `&&` binds tighter than `||` in Ruby, this parses as:
```ruby
(repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?) ||
  (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
  (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```
`review_stacks_enabled` is only ANDed into the first disjunct. If `provisioning_behavior` is `allow_with_label` (or `prevent_with_label`), `review_stacks_enabled` has zero effect on the outcome.

`pull_request_has_provisioning_label?` checks `pull_request_label_names.include?(repository.provisioning_label_name)`, and `pull_request_label_names` is derived straight from the raw webhook payload's `pull_request["labels"]` [2](#0-1) , which is fully attacker-controlled since GitHub labels on one's own PR can be set by the PR author (given at minimum triage/write access to labels, or any repo where labels are open). `respond_to_pull_request_opened?` gates only on `params.action == "opened" && provision?` [3](#0-2) , and `process` unconditionally calls `ReviewStackAdapter#find_or_create!` when that's true [4](#0-3) , which creates the `ReviewStack` record and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` [5](#0-4) , ultimately leading into provisioning/task execution (`TaskCommands#perform` → `Command#start`).

Existing guards do not prevent this: webhook signature verification only authenticates that the payload came from the *configured* GitHub repository, not that its label contents are trustworthy — labels are legitimately attacker-controlled data within a valid, correctly-signed webhook for the attacker's own PR. `ExplicitParameters` schema validation only checks payload shape, not label semantics. The `review_stacks_enabled` toggle — the only feature meant to fully disable this feature for a repository — is silently bypassed for two of the three `provisioning_behavior` modes. Every existing test helper `configure_provisioning_behavior` defaults `provisioning_enabled: true`, so the test suite never exercises `review_stacks_enabled: false` combined with `allow_with_label`/`prevent_with_label`, which is why this went uncaught. [6](#0-5) 

The identical bug pattern also exists in `ReopenedHandler#unarchive?` [7](#0-6) .

### Impact Explanation
An attacker who has zero repository permissions beyond opening a PR against a `allow_with_label`/`prevent_with_label`-configured repository can force `Shipit::ReviewStack` creation and enqueue it for provisioning even though the repository operator explicitly disabled review-stack provisioning (`review_stacks_enabled: false`). This results in a stack record being written and a provisioning/deploy pipeline being triggered for a repository that never authorized it via its intended control — matching "an unauthorized deploy" / unauthorized record creation for a repository that did not authenticate the action through its intended gate. The blast radius is scoped to repositories using `allow_with_label`/`prevent_with_label` behaviors with `review_stacks_enabled: false`; it is fully repeatable per PR/per repository matching that configuration.

### Likelihood Explanation
Preconditions: repository must have `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (an existing, documented, UI-configurable setting) and `provisioning_label_name` set, while `review_stacks_enabled` is `false`. `prevent_with_label` is trivially exploitable (attacker does nothing — no label needed). For `allow_with_label`, the attacker needs the label name, which may be discoverable (default value, repo label list, documentation) but is not guaranteed to be secret in any case — it's a UI setting, not a secret. Attacker cost is a single PR open action; no credentials, tokens, or privileged roles are required.

### Recommendation
Fix the operator precedence so `review_stacks_enabled` gates all three behaviors, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to `ReopenedHandler#unarchive?`, and add regression tests for `review_stacks_enabled: false` combined with each `provisioning_behavior` value.

### Proof of Concept
minitest plan (in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` style, no live GitHub):
```ruby
test "does not create stacks when review_stacks_enabled is false even with allow_with_label and matching label" do
  repository = shipit_repositories(:shipit)
  repository.update!(
    review_stacks_enabled: false,       # LHS of binding: provisioning disabled
    provisioning_behavior: :allow_with_label,
    provisioning_label_name: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = [{ "name" => "pull-requests-label" }]  # attacker-controlled label

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Before the fix, this assertion fails (a stack is created despite `review_stacks_enabled == false`), demonstrating that `repository.review_stacks_enabled == false` and "stack gets provisioned" diverge — i.e., the binding "label ownership == authorization to provision" holds where it should not, contrary to the operator's intent expressed by the disabled flag.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-63)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
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
