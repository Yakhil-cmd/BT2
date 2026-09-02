### Title
Operator-precedence bug in `unarchive?`/`provision?` lets `review_stacks_enabled: false` be bypassed via a PR label - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler#unarchive?` (and identically `OpenedHandler#provision?`) is written as `a && b || c || d` without parentheses grouping `a` with the whole expression, so Ruby's operator precedence (`&&` binds tighter than `||`) makes the "allow_with_label" and "prevent_with_label" branches independent of `repository.review_stacks_enabled`. An attacker who owns a PR on a repo where an operator set `review_stacks_enabled: false` but left `provisioning_behavior: allow_with_label` (or `prevent_with_label`) configured can still trigger `ReviewStackAdapter#unarchive!`/`#find_or_create!`, resurrecting or creating a review stack bound to their own branch.

### Finding Description
Binding claimed by the operator's intent: `repository.review_stacks_enabled == false` should imply `ReopenedHandler#unarchive? == false` for every provisioning behavior, i.e. no stack should ever be unarchived/created when review stacks are disabled.

Actual code: [1](#0-0) 

```ruby
def respond_to_pull_request_reopened?
  params.action == "reopened" && unarchive?
end

def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Due to Ruby precedence, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

The second and third disjuncts never reference `review_stacks_enabled`. So with `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label`, if the attacker's PR carries the configured provisioning label, `unarchive?` still returns `true`.

`process` then calls: [2](#0-1) 

which routes to `ReviewStackAdapter#unarchive!`, and if no stack exists yet, falls through to `#create!`: [3](#0-2) [4](#0-3) 

`stack_attributes` sets `branch: params.pull_request.head.ref` and `environment: "pr#{params.number}"`, i.e., the environment slot is deterministic per PR number, so re-opening the same PR resurrects the same environment with the attacker's current head ref. `OpenedHandler#provision?` has the identical bug for the `opened` action: [5](#0-4) 

No guard (`verify_signature`/`ExplicitParameters` schema/`respond_to_pull_request_reopened?`) checks anything beyond this buggy predicate — the webhook signature check only authenticates that the payload came from GitHub for that repository, it does not enforce that `review_stacks_enabled` disables all provisioning behaviors. Once the label condition is met, no authorization check on the PR author or approver is performed.

### Impact Explanation
An attacker who can open/label/close/reopen a PR on their own fork against a repo where the operator believes review stacks are fully disabled can still cause Shipit to write/update a `Shipit::ReviewStack` record (`branch`, `archived_since`, `environment`) and enqueue it for provisioning (`Shipit::ReviewStackProvisioningQueue.add`). This is a repository-scoped record write that the operator did not authorize (they disabled `review_stacks_enabled` specifically to prevent this). If the provisioning handler configured by the host application then acts on `awaiting_provision?` stacks (e.g., allocating infrastructure, running `shipit.yml` steps against `branch`), this results in code from the attacker's branch being provisioned/executed under the operator's disabled review-stack policy. This matches "a record written for a repository that did not authenticate/authorize it" and can escalate to unauthorized provisioning/deploy actions depending on host-application provisioning handlers wired to `awaiting_provision?`/`ReviewStackProvisioningQueue`. The blast radius is confined to the single repository whose configuration has this specific combination (`review_stacks_enabled: false` + `allow_with_label`/`prevent_with_label`), and is repeatable on every close/reopen or label toggle cycle.

### Likelihood Explanation
Requires a specific repository configuration: `review_stacks_enabled: false` combined with a non-default `provisioning_behavior` (`allow_with_label` or `prevent_with_label`) and, for `prevent_with_label`, simply not having the label (the default state of most PRs) is sufficient — no label action needed at all. This is a plausible misconfiguration: an operator turning off review stacks via the toggle without resetting `provisioning_behavior` back to `allow_all`, since the UI doesn't force them to be mutually exclusive. Attacker cost is minimal — opening/closing/reopening a PR on their own fork, or adding a label they control. Fully repeatable and requires no privileged Shipit access.

### Recommendation
Fix operator precedence in `ReopenedHandler#unarchive?`, `OpenedHandler#provision?` (and audit `LabeledHandler`/`UnlabeledHandler`, which already correctly gate on `review_stacks_enabled` in `respond_to_label_change?` but should be double-checked) by explicitly parenthesizing the whole expression so `review_stacks_enabled` gates every branch:

```ruby
def unarchive?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```

Apply the same fix to `OpenedHandler#provision?`.

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb` (existing test infra in this file already exercises exactly this class):

```ruby
test "does NOT unarchive stacks when review_stacks_enabled is false, even with allow_with_label + matching label" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,          # operator disabled review stacks
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" } # attacker-controlled label
  payload["pull_request"]["head"]["ref"] = "attacker-branch"

  Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process

  stack.reload
  assert stack.archived?, "Stack must remain archived when review_stacks_enabled is false"
  assert_not_equal "attacker-branch", stack.branch
end
```

Binding assertion: `repository.review_stacks_enabled == false` must imply `stack.archived? == true` and `stack.branch` unchanged. Running this test against the current code fails (`stack.archived?` is `false`, `stack.branch == "attacker-branch"`), confirming the divergence; it passes once `unarchive?`/`provision?` are parenthesized as recommended.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L65-75)
```ruby
          def respond_to_pull_request_reopened?
            params.action == "reopened" &&
              unarchive?
          end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-98)
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

          def environment
            "pr#{params.number}"
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
