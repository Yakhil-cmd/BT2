### Title
Operator precedence bug in `OpenedHandler#provision?` bypasses `review_stacks_enabled` when `provisioning_behavior` is `allow_with_label`/`prevent_with_label` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` combines `repository.review_stacks_enabled` with the three provisioning behaviors using `&&`/`||` without parentheses around the enable flag, so Ruby's operator precedence only gates the `allow_all?` branch. When a repository has `review_stacks_enabled == false` but `provisioning_behavior == allow_with_label` (or `prevent_with_label`), an attacker who labels their own PR with the configured `provisioning_label_name` can still trigger `ReviewStackAdapter#find_or_create!`, creating and queuing a review stack for provisioning even though the operator disabled review stacks.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == false` should imply `provision? == false` for every `provisioning_behavior` value. In the actual code: [1](#0-0) 

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` binds tighter than `||`, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)`

`review_stacks_enabled` is only ANDed into the first disjunct. The `allow_with_label?` and `prevent_with_label?` branches are evaluated independently of `review_stacks_enabled`, so they can be `true` even when review stacks are disabled for the repository. `ReopenedHandler#unarchive?` has the identical bug pattern: [2](#0-1) 

By contrast, `LabeledHandler#respond_to_label_change?` gates correctly by ANDing `review_stacks_enabled` as a top-level condition around the whole `(archive? || unarchive?)` expression: [3](#0-2) 

confirming the intended semantics and that `OpenedHandler`/`ReopenedHandler` deviate from it.

Exploit flow: operator sets `repository.review_stacks_enabled = false`, `provisioning_behavior = :allow_with_label`, `provisioning_label_name = "some-label"` (all visible via the Shipit repository settings UI, per the question's stated preconditions). An attacker opens a pull request on that repository and adds the label `"some-label"` to it (attacker-controlled action on their own PR). GitHub emits a legitimate, signed `pull_request` "opened" webhook containing `pull_request.labels = [{"name": "some-label"}]`. `OpenedHandler#pull_request_has_provisioning_label?` reads `pull_request["labels"]` directly from the payload: [4](#0-3) 

`provision?` evaluates true despite `review_stacks_enabled == false`, and `ReviewStackAdapter#find_or_create!` creates a `ReviewStack` using `params.pull_request.head.ref` as the branch and queues it for provisioning: [5](#0-4) 

No existing guard prevents this: webhook signature verification only authenticates that the event genuinely came from GitHub for that repository, it does not validate the semantic combination of `review_stacks_enabled` and `provisioning_behavior`; there is no model validation coupling those two attributes; and `ExplicitParameters` only validates payload shape, not business logic.

### Impact Explanation
The attacker gets an unauthorized `Stack`/`ReviewStack` created and queued for provisioning on a repository the operator explicitly disabled for review-stack automation, using a branch (`head.ref`) and PR content fully controlled by the attacker. Once provisioned/deployed, the stack's `shipit.yml`, deploy scripts, and CI/task commands run under the deploy host's `Command`/`PTY.spawn` execution with attacker-controlled content from their own fork/branch, which is the RCE path this engine relies on for legitimate review-stack provisioning. This is repeatable against any repository misconfigured with `review_stacks_enabled: false` + `allow_with_label`/`prevent_with_label`, by any external GitHub user able to open a PR and label it.

### Likelihood Explanation
Requires a specific but plausible operator misconfiguration: `review_stacks_enabled = false` combined with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (e.g., an operator temporarily disabling review stacks without reverting the behavior setting, or never having set `allow_all`). The `provisioning_label_name` is visible via the Shipit UI as stated in the question's preconditions. Attacker cost is trivial: open a PR and add a label matching a known/discoverable string, or (for `prevent_with_label`) simply avoid adding a label at all — no special GitHub permissions or Shipit credentials required beyond opening a PR in a public repo.

### Recommendation
Fix operator precedence by parenthesizing the enable check around the whole expression, matching the `LabeledHandler` pattern:

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
```ruby
test "does not create stacks for repos that allow_with_label when review_stacks_enabled is false" do
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
With the current code, `Shipit::Stack.count` increases despite `review_stacks_enabled == false`, demonstrating the broken binding; after applying the recommended fix, the assertion passes.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-78)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
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
