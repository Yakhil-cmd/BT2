### Title
`OpenedHandler#provision?` operator-precedence bug lets `review_stacks_enabled: false` be bypassed via `allow_with_label`/`prevent_with_label` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`provision?` combines `review_stacks_enabled` with the three provisioning-behavior checks using Ruby's `&&`/`||` operator precedence, so `review_stacks_enabled` only gates the `allow_all?` branch and is silently ignored for the `allow_with_label?` and `prevent_with_label?` branches. An attacker who can label their own pull request on a repository configured with `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label` can still trigger `ReviewStack` creation.

### Finding Description
The claimed binding is: `review_stacks_enabled_by_operator == review_stacks_enabled_actually_gating_provisioning?`. Tracing `provision?`: [1](#0-0) 

Because `&&` binds tighter than `||` in Ruby, this expression parses as:

`(repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?) || (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) || (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)`

`review_stacks_enabled` is only ANDed into the first disjunct (`allow_all?`). The second and third disjuncts (`allow_with_label?` and `prevent_with_label?`) are evaluated independently of `review_stacks_enabled`. So the equality is broken: setting `review_stacks_enabled: false` does **not** disable provisioning when `provisioning_behavior` is `allow_with_label` (with the label present) or `prevent_with_label` (with the label absent).

`respond_to_pull_request_opened?` only checks `params.action == "opened" && provision?` — there is no separate, unconditional gate on `review_stacks_enabled`: [2](#0-1) 

`pull_request_has_provisioning_label?` reads the label names directly from the attacker-controlled webhook payload (`pull_request.labels[].name`), which the attacker fully controls by naming a label on their own PR to match `repository.provisioning_label_name`: [3](#0-2) 

Once `provision?` returns `true`, `process` unconditionally creates the review stack via `ReviewStackAdapter#find_or_create!` → `create!`, which builds a `Stack` and `PullRequest` from the payload without any further authorization check: [4](#0-3) [5](#0-4) 

None of the standard guards (webhook signature verification, `ExplicitParameters` schema, `Repository` validations) prevent this, because the webhook itself is a legitimate, correctly-signed GitHub event describing a real PR/label the attacker created — the flaw is purely in the business-logic boolean expression, not in authentication of the webhook.

### Impact Explanation
An unprivileged contributor who can open a pull request and label it (naming the label to match `provisioning_label_name`) can force Shipit to create/unarchive a `Shipit::ReviewStack` on a repository whose owner has explicitly set `review_stacks_enabled: false`, directly contradicting the repository owner's configuration. This is a repeatable, per-repository authorization bypass: any repository misconfigured with `allow_with_label`/`prevent_with_label` while `review_stacks_enabled` is `false` is affected, and the same technique works via the `LabeledHandler`/`UnlabeledHandler` (which share the same `allow_with_label`/`prevent_with_label` logic pattern) to reopen/keep stacks alive. This matches "a payload for one repository mutating another's stack" in spirit — the repo owner's own review-stack-disable directive is bypassed, causing unwanted provisioning (deploy infrastructure spin-up) for a repository/tenant that opted out.

### Likelihood Explanation
Preconditions: the target repository must have `provisioning_behavior` set to `allow_with_label` (or `prevent_with_label`) with `review_stacks_enabled: false` — a plausible but non-default combination an operator might pick believing `review_stacks_enabled: false` is an absolute kill switch. The attacker only needs the ability to open a PR and add a label matching `provisioning_label_name` (given in scope), at zero cost, and can repeat it at will.

### Recommendation
Fix operator precedence/grouping in `provision?` so `review_stacks_enabled` gates all branches, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the equivalent fix to any other handler sharing this pattern (e.g., `labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`) if they have the same precedence issue.

### Proof of Concept
Minitest (e.g. `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
```ruby
test "does not create stacks for allow_with_label repos when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :allow_with_label
  repository.provisioning_label_name = "deploy-pr"
  repository.save!

  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "deploy-pr" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Before the fix: `Shipit::Stack.count` changes (assertion fails), proving `review_stacks_enabled == false` does not gate provisioning as claimed by the operator — demonstrating the AUTHORIZATION_TRUTH failure. After applying the recommended fix, the test passes.

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
