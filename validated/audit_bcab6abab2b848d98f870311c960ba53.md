Confirmed: no `review_stacks_enabled` check exists anywhere in the create path other than the buggy `provision?` boolean expression.

### Title
`ReviewStack` provisioning bypasses `review_stacks_enabled` due to operator-precedence bug in `provision?` - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`PullRequest::OpenedHandler#provision?` combines `review_stacks_enabled` with `provisioning_behavior_allow_all?` using `&&`, then `||`s in the `allow_with_label` and `prevent_with_label` branches without re-checking `review_stacks_enabled`. Because Ruby's `&&` binds tighter than `||`, any repository with `provisioning_behavior: allow_with_label` (or `prevent_with_label`) will provision a `ReviewStack` for a PR regardless of whether `review_stacks_enabled` is `true` or `false`.

### Finding Description
The binding that must hold is: `repository.review_stacks_enabled == true` before `Shipit::ReviewStack.create!` runs for that repository. The actual code is: [1](#0-0) 
which Ruby parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. The last two disjuncts never reference `review_stacks_enabled`. `respond_to_pull_request_opened?` calls this directly and `process` invokes `ReviewStackAdapter#find_or_create!` on a positive result: [2](#0-1) 
`ReviewStackAdapter#create!` builds the `ReviewStack` from `params.pull_request.head.ref` and the PR number, with no further check of `review_stacks_enabled`: [3](#0-2) 
`Repository#review_stacks_enabled` is a plain column and `provisioning_behavior` is an independent enum; nothing else in the model or controller layer re-validates the combination: [4](#0-3) 
An attacker who forks a target repository configured with `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label` (a state an operator could set, e.g. while review stacks were previously enabled or misconfigured), opens a PR from their fork, and applies the label named by `repository.provisioning_label_name` to their own PR, causes a `ReviewStack` to be created and queued for provisioning even though the repository operator disabled review stacks. Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) only validate webhook authenticity/shape, not this authorization semantics, so they do not prevent the divergence.

### Impact Explanation
This results in a `ReviewStack`/`Stack` record and CI provisioning being triggered for a repository whose operator explicitly disabled review stacks (`review_stacks_enabled: false`), i.e., a mutation authorized only by an unprivileged PR author, not by the repository's operator-controlled feature flag. Once provisioned, the stack proceeds through the standard review-stack provisioning/deploy pipeline, ultimately executing the attacker-controlled `shipit.yml` from their fork's branch via `TaskCommands`/`Command#start`/`PTY.spawn`, i.e., attacker-controlled code execution on the deploy host. This is repeatable against any repository sharing this misconfiguration (`review_stacks_enabled: false` + `provisioning_behavior_allow_with_label?`/`prevent_with_label?`), and each PR opened with the qualifying label (or without it in the `prevent_with_label` case) triggers a new bypass. This matches the Critical impact category of "a payload for one repository mutating another's [operator] authorization" / RCE via `Command`/`PTY.spawn`.

### Likelihood Explanation
Preconditions require a target repository already configured with `review_stacks_enabled: false` and `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` — a non-default but reachable admin-set state via the repository settings UI (e.g., operator disables review stacks after having configured a provisioning behavior, or sets provisioning_behavior without realizing the toggle is decoupled). No Shipit credentials, session, or GitHub App secrets are needed by the attacker; forking a public repo, opening a PR, and adding a label are actions available to any unprivileged GitHub user. The bug is 100% deterministic given the config state — not probabilistic — making it fully reproducible.

### Recommendation
Add explicit parentheses / an outer `review_stacks_enabled &&` guard covering all three disjuncts, e.g.:
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
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, add:
```ruby
test "does not provision a review stack when review_stacks_enabled is false, even with allow_with_label + matching label" do
  repository = shipit_repositories(:shipit)
  repository.update!(review_stacks_enabled: false, provisioning_behavior: :allow_with_label, provisioning_label_name: "deploy-preview")

  params = build_pull_request_opened_params(repository: repository, labels: [{ name: "deploy-preview" }])
  handler = Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(params)

  assert_equal repository.review_stacks_enabled, false
  handler.process
  assert_not Shipit::ReviewStack.exists?(environment: "pr#{params.number}"),
    "expected review_stacks_enabled == false to prevent ReviewStack creation, but a stack was created"
end
```
This asserts both sides of the binding — `repository.review_stacks_enabled == false` before, and `Shipit::ReviewStack.exists?(...) == false` after — currently the assertion fails under the vulnerable code because a stack is created.

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

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
```
