### Title
`provision?` operator-precedence bug lets `prevent_with_label`/`allow_with_label` behaviors bypass `review_stacks_enabled=false` - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`OpenedHandler#provision?` only ANDs `repository.review_stacks_enabled` with the first disjunct (`provisioning_behavior_allow_all?`), not with the second or third disjuncts. As a result, when a repository has `review_stacks_enabled=false` but `provisioning_behavior` set to `allow_with_label` or `prevent_with_label`, an attacker-controlled PR can still satisfy `provision?` and trigger `ReviewStackAdapter#create!`, creating a `Shipit::Stack`/`ReviewStack` and enqueuing it for provisioning even though the repository's master review-stacks switch is off.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled (== false)` should equal the boolean that gates all stack creation via `ReviewStackAdapter#create!`. In the actual code: [1](#0-0) 

Due to Ruby's `&&`/`||` precedence, this evaluates as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)`

`review_stacks_enabled` is scoped only to the first disjunct. For `provisioning_behavior = :prevent_with_label` with `review_stacks_enabled = false` and an empty `pull_request.labels` array (`pull_request_has_provisioning_label?` returns false via [2](#0-1) ), the third disjunct evaluates true, making `provision?` true and `respond_to_pull_request_opened?` true ( [3](#0-2) ). `process` then calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` ( [4](#0-3) ), which creates a stack and pull request record and adds it to `Shipit::ReviewStackProvisioningQueue` ( [5](#0-4) ).

The attacker's action is simply opening a PR with no labels (or removing labels) against any repository whose maintainer has configured `provisioning_behavior=:prevent_with_label` and `review_stacks_enabled=false` — a configuration state that the settings UI presents as "provisioning disabled" via the single `review_stacks_enabled` toggle (`app/views/shipit/repositories/settings.html.erb`). No webhook signature bypass is needed for this specific finding — a maintainer legitimately configures this state, and any external contributor opening a PR (unprivileged) triggers unwanted stack creation. Existing guards (`verify_signature`, `ExplicitParameters`, model validations) are irrelevant here because the vulnerability is in the boolean composition of `provision?` itself, not in payload authentication.

### Impact Explanation
An attacker who can open a PR (fork PR, no special permission) against a repository configured with `review_stacks_enabled=false` + `provisioning_behavior=:prevent_with_label` (or similarly `allow_with_label` combined with a labeled PR, though that path requires label-add permission) causes a `Shipit::Stack`/`ReviewStack` record to be created and queued for provisioning (`Shipit::ReviewStackProvisioningQueue.add(stack)`), even though the repository owner explicitly disabled review-stack auto-provisioning. Downstream, provisioning eventually drives `Command`/deploy execution for that stack. This is an unauthorized-action bypass of the intended "master switch," matching the Critical category ("a record written for a repository that did not authenticate it" / "an unauthorized deploy"), repeatable on every PR the attacker opens with empty labels against any repository sharing this configuration.

### Likelihood Explanation
Preconditions are entirely repository-configuration-driven: the maintainer must set `provisioning_behavior=:prevent_with_label` (or `allow_with_label`) while leaving `review_stacks_enabled=false`, believing this fully disables auto-provisioning. Given the settings UI groups these as independent controls, this is a plausible/likely misconfiguration. Attacker cost is trivial — open a PR with no labels (default state) — and repeatable per-PR, per-repository.

### Recommendation
Fix operator grouping in `provision?` so `repository.review_stacks_enabled` gates all three disjuncts, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does not create stacks when review_stacks_enabled is false, even for prevent_with_label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Binding before fix: `repository.review_stacks_enabled == false` vs. actual gate for stack creation `== true` (mismatch, `assert_difference` currently passes, proving bypass). After fix, both sides equal `false`, and `assert_no_difference` passes.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L72-74)
```ruby
          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
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
