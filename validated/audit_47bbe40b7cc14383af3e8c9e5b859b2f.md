### Title
`provision?` operator-precedence bug bypasses `review_stacks_enabled` gate for `allow_with_label`/`prevent_with_label` repos - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`OpenedHandler#provision?` intends `review_stacks_enabled` to gate all three provisioning behaviors, but Ruby's `&&`/`||` precedence only binds it to the `allow_all` branch. On a repository configured with `provisioning_behavior: allow_with_label` and `review_stacks_enabled: false`, a pull request carrying a label matching `provisioning_label_name` still causes a `Stack` to be created and queued for provisioning.

### Finding Description
The intended binding is: `review_stacks_enabled == true` must hold for **any** stack to be auto-provisioned from a pull request, regardless of which `provisioning_behavior` is configured.

The actual code:
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Because `&&` binds tighter than `||`, this parses as:
```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)
```
`review_stacks_enabled` is only ANDed into the first disjunct. The second and third disjuncts (`allow_with_label?`/`prevent_with_label?` branches) are evaluated completely independently of `review_stacks_enabled`.

`pull_request_has_provisioning_label?` simply checks whether any label name on the incoming payload equals `repository.provisioning_label_name`:
```ruby
def pull_request_has_provisioning_label?
  pull_request_label_names.include?(repository.provisioning_label_name)
end

def pull_request_label_names
  Array.new(pull_request["labels"]).map { |label| label["name"] }
end
``` [2](#0-1) 

`respond_to_pull_request_opened?` gates `process`, which calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!`, which creates a `Stack` and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` if one doesn't already exist: [3](#0-2) [4](#0-3) 

There is no additional `review_stacks_enabled` check anywhere else along this path — `Repository` model itself has no such guard method, only the enum-derived predicates (`provisioning_behavior_allow_all?`, etc.) shown in `app/models/shipit/repository.rb` lines 21-31/50-51. [5](#0-4) 

**Exploit flow**: a repository is registered in Shipit with `provisioning_behavior: allow_with_label`, `provisioning_label_name: "deploy-preview"`, and `review_stacks_enabled: false` (operator intends this combination to be inert, believing the disabled flag suppresses all auto-provisioning). An attacker opens a pull request against that repository and labels it `deploy-preview` (per the threat model, attacker can label their own PR). The `pull_request.opened` webhook is legitimately signed by GitHub (no signature bypass required — this is a real webhook from a real, tracked repository). `provision?` evaluates the second disjunct (`allow_with_label? && has_label?`) as `true` independent of `review_stacks_enabled`, so `respond_to_pull_request_opened?` returns `true`, and a `Stack` is created and queued for provisioning, which will eventually execute deploy commands against the attacker-controlled branch/`shipit.yml`.

Existing guards (`verify_signature`/`GitHubApp#verify_webhook_signature`, `ExplicitParameters` schema, `drop_unhandled_event`) do not address this: they validate payload shape and webhook authenticity, not the `review_stacks_enabled` business-logic gate, which is broken purely by the precedence bug.

### Impact Explanation
A `Stack` record is created and queued for provisioning for a repository that the operator explicitly configured as `review_stacks_enabled: false`, i.e., a config believed to prevent any auto-provisioned deploy stacks. Provisioning proceeds to read the attacker-supplied `shipit.yml` from the PR branch and execute deploy-time commands (via the provisioning queue/task pipeline), constituting unauthorized deploy-time command execution driven entirely by attacker-controlled PR content. This is repeatable against any repository sharing this misconfiguration (`allow_with_label` or `prevent_with_label` + `review_stacks_enabled: false`) and requires no privileges beyond opening/labeling a PR on that repository.

### Likelihood Explanation
Preconditions: the target repository must be tracked by Shipit and configured with `provisioning_behavior: allow_with_label` (or `prevent_with_label`) while `review_stacks_enabled: false`, and a `provisioning_label_name` must be set. This is a plausible/realistic operator misconfiguration since the UI/model treats `review_stacks_enabled` as the master switch and `provisioning_behavior`/`provisioning_label_name` as sub-settings meant to only matter when review stacks are enabled. Attacker cost is trivial — open a PR and add a label (or, for `prevent_with_label`, simply not add a label) on their own fork submission against the misconfigured repo — and the exploit is fully repeatable per PR/branch.

### Recommendation
Fix operator precedence by explicitly parenthesizing the intended grouping so `review_stacks_enabled` gates all three branches:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the equivalent fix to any other handler with the same pattern (`labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb` — all matched `provisioning_behavior`/`review_stacks_enabled` in the grep results and should be audited for the same precedence bug).

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` (mirroring `"creates stacks for repos that allow_with_label when label is present"`):
```ruby
test "does not create stacks for allow_with_label repos when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,  # review_stacks_enabled = false
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
Binding under test: `repository.review_stacks_enabled == false` should imply `Shipit::Stack.count` unchanged. With the current code, this assertion **fails** (`Stack.count` increases by 1), demonstrating the bug; after applying the recommended fix, the assertion passes.

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

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
```
