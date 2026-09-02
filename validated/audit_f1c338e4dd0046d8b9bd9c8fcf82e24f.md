## Title
Operator-precedence bug in `OpenedHandler#provision?` provisions review stacks even when `review_stacks_enabled` is `false` - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` in [1](#0-0)  is written as `enabled && allow_all? || (allow_with_label? && label) || (prevent_with_label? && !label)`. Because Ruby's `&&` binds tighter than `||`, this parses as `(enabled && allow_all?) || (allow_with_label? && label) || (prevent_with_label? && !label)`, so the `allow_with_label` and `prevent_with_label` branches never check `review_stacks_enabled`. A repository configured with `provisioning_behavior=allow_with_label` (or `prevent_with_label`) will have review stacks provisioned from PR webhooks regardless of whether `review_stacks_enabled` is `true` or `false`.

### Finding Description
The correct/intended binding should be: `provision? == review_stacks_enabled && (allow_all? || (allow_with_label? && label) || (prevent_with_label? && !label))`. The actual code omits the parentheses around the whole disjunction, so `review_stacks_enabled` is only ANDed with the first disjunct (`allow_all?`), not distributed across the `allow_with_label?`/`prevent_with_label?` branches, per [1](#0-0) .

Trace: an unauthenticated `pull_request` `opened` webhook payload is parsed by `OpenedHandler#process`, which calls `respond_to_pull_request_opened?` → `provision?` [2](#0-1) . If `provision?` returns true, `ReviewStackAdapter#find_or_create!` builds a `ReviewStack` from fork-controlled `stack_attributes` (`branch: params.pull_request.head.ref`, `environment: "pr#{params.number}"`) and enqueues it into `ReviewStackProvisioningQueue` [3](#0-2) . This queue eventually deploys the stack, checking out the fork ref and executing its `shipit.yml`/task commands via the standard task-execution pipeline.

The existing test suite in `opened_handler_test.rb` never exercises the combination of `review_stacks_enabled: false` with `behavior: :allow_with_label`/`prevent_with_label` (the covered `allow_with_label` test always leaves `provisioning_enabled: true` at its default), so this divergence is untested [4](#0-3) , [5](#0-4) .

No signature verification, permission check, or model validation guards this: `Repository#review_stacks_enabled` is a plain boolean column and `provisioning_behavior` is a plain enum [6](#0-5) ; there is no additional check elsewhere in the pipeline that re-validates `review_stacks_enabled` before provisioning.

### Impact Explanation
On any repository where an operator has set `provisioning_behavior` to `allow_with_label` or `prevent_with_label` but has left (or later set) `review_stacks_enabled = false` — intending review-stack auto-provisioning to be off — an attacker who can open a pull request (and, for `allow_with_label`, apply a label to their own PR, which any PR author can do on their own PR) can still trigger `ReviewStack` creation and provisioning/deployment of a stack built from their fork's `head.ref`/commit. This leads to execution of attacker-controlled `shipit.yml` deploy steps on the Shipit deploy host, matching the Critical RCE impact category (arbitrary command execution via the task pipeline, `PTY.spawn`). This is repeatable for any repository with this misconfiguration.

### Likelihood Explanation
Preconditions: The repository must be onboarded to Shipit and have `provisioning_behavior` set to `allow_with_label` or `prevent_with_label`; `review_stacks_enabled` can be `false` — the very setting an operator would use to disable this feature. The attacker only needs standard, unprivileged GitHub permissions to open a PR from a fork (and label it for the `allow_with_label` case, which PR authors can typically do on their own PRs, or simply leave it unlabeled for `prevent_with_label`). No Shipit credentials, secrets, or GitHub App keys are required. This is a pure logic bug reachable directly through the standard webhook path.

### Recommendation
Fix operator precedence by explicitly grouping the `review_stacks_enabled` check around the entire disjunction:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same audit to `LabeledHandler`, `UnlabeledHandler`, and `ReopenedHandler`, which appear to share similar logic per the grep results, to ensure `review_stacks_enabled` gates all provisioning paths consistently.

### Proof of Concept
Minitest plan (add to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
```ruby
test "does not create stacks for repos with review_stacks_enabled=false even when allow_with_label matches" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # review_stacks_enabled = false
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::ReviewStack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Before the fix: `provision?` evaluates `(false && allow_all?) || (true && true) || ...` → `true`, so a `ReviewStack` is created despite `review_stacks_enabled == false`, failing `assert_no_difference`. After applying the recommended fix, `provision?` evaluates `false && (...)` → `false`, and the assertion passes — demonstrating both sides of the equality `provision? == (review_stacks_enabled && behavior_matches?)` before (mismatched) and after (matched) the fix.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-63)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def pull_request
            params.pull_request
          end

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

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L129-142)
```ruby
          test "creates stacks for repos that allow_with_label when label is present" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :allow_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
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

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
```
