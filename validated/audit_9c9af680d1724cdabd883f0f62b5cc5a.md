### Title
`provision?` fails to gate `allow_with_label`/`prevent_with_label` disjuncts on `review_stacks_enabled` due to `&&`/`||` precedence - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`provision?` in `OpenedHandler` is written as `a && b || c || d`, so Ruby's operator precedence binds `repository.review_stacks_enabled` only to the first disjunct (`allow_all`). The `allow_with_label` and `prevent_with_label` disjuncts are entirely independent of `review_stacks_enabled`, so an attacker who opens/labels a pull request on a repository configured with `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label` (or `prevent_with_label`) can still cause `ReviewStackAdapter#create!` to run and create a `Shipit::ReviewStack` and its provisioning queue entry.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == true` must gate all three disjuncts of `provision?`. Tracing the code: [1](#0-0) 

Due to Ruby precedence (`&&` binds tighter than `||`), this evaluates as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

So for `review_stacks_enabled: false`:
- If `provisioning_behavior: allow_with_label` and the PR carries the configured label, `provision?` is `false || true || false == true`.
- If `provisioning_behavior: prevent_with_label` and the PR lacks the label, `provision?` is `false || false || true == true`.

Either way, `respond_to_pull_request_opened?` returns true and `process` calls `ReviewStackAdapter#create!`, which runs `scope.create!(stack_attributes)` and enqueues `Shipit::ReviewStackProvisioningQueue.add(stack)`: [2](#0-1) [3](#0-2) 

Nothing else in the path re-checks `review_stacks_enabled`. Existing guards (`params.action == "opened"`, `ExplicitParameters` schema, `respond_to_pull_request_opened?`) only validate payload shape and PR action, not the review-stacks-enabled flag for the label-based branches. `NullRepository#review_stacks_enabled` returning `false` is irrelevant here since the target repo exists and is found via `Repository.from_github_repo_name`.

The attacker's action: open a pull request (or ensure the label state matches) against any repository the operator has configured this way; the label itself (`pull_request.labels[].name`) is attacker-controlled since the PR author (an unprivileged GitHub user opening a PR from their own fork) can typically add labels to their own PR or the repo may auto-apply one, and for `prevent_with_label` the attacker simply needs to *not* add the label, which requires no privilege at all.

### Impact Explanation
A malformed/misconfigured-but-plausible operator setting (`review_stacks_enabled: false` combined with `allow_with_label` or `prevent_with_label`) results in a `Shipit::ReviewStack` and provisioning job being created for that repository despite the operator's explicit intent to disable review stacks. This is a real "record written that should not be written" bug — it creates infrastructure provisioning work (`Shipit::ReviewStackProvisioningQueue.add`) for a repository whose operator disabled review stacks, which can lead to actual deploy/provisioning actions being kicked off. This matches "unauthorized deploy" class impact scoped to the affected repository; there is no cross-tenant/cross-repository impact since `repository` is strictly resolved from `params.repository.full_name` and the scope is `repository.review_stacks`.

### Likelihood Explanation
Requires the specific operator misconfiguration named in the question (`provisioning_behavior` in `{allow_with_label, prevent_with_label}` while `review_stacks_enabled: false`). This is a plausible operator error precisely because the UI/model exposes these as two independent settings without enforcing that `review_stacks_enabled` gates all provisioning behaviors. Given that precondition, the attacker's cost is trivial (open a PR, optionally add/omit a label they control), fully repeatable, and requires no secrets or privileged role — consistent with the attacker model in the prompt.

### Recommendation
Fix `provision?` to make `review_stacks_enabled` the single top-level gate, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (
      repository.provisioning_behavior_allow_all? ||
      (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
      (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
    )
end
```

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does not create stack when review_stacks_enabled is false and behavior is allow_with_label with label present" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    review_stacks_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::ReviewStack.count } do
    OpenedHandler.new(payload).process
  end
end

test "does not create stack when review_stacks_enabled is false and behavior is prevent_with_label with label absent" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    review_stacks_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  assert_no_difference -> { Shipit::ReviewStack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Both assertions currently fail against the present `provision?` implementation (stacks get created), demonstrating the precedence bug; they pass once `provision?` is wrapped as recommended above.

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
