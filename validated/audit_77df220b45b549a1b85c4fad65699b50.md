### Title
`OpenedHandler#provision?` ignores `review_stacks_enabled` for the `prevent_with_label` branch, allowing review-stack creation despite auto-provisioning being disabled - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` is written as `A && B || C || D` where Ruby's operator precedence makes `&&` bind tighter than `||`, so the expression parses as `(A && B) || C || D`. The third disjunct, `(repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)`, is fully parenthesized and never references `repository.review_stacks_enabled` at all, so it can independently return `true` even when `review_stacks_enabled` is `false`.

### Finding Description
The binding claimed to hold everywhere is `repository.review_stacks_enabled == true` for every created `ReviewStack`. Tracing the code: [1](#0-0) 

parses (per Ruby precedence rules) as:
```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)
```
The third clause has no dependency on `review_stacks_enabled`. With `provisioning_behavior: :prevent_with_label`, `provisioning_label_name: 'x'`, `review_stacks_enabled: false`, and an unlabeled PR, the third clause evaluates `true`, `provision?` returns `true`, and `respond_to_pull_request_opened?` proceeds. [2](#0-1) 

`process` then calls `ReviewStackAdapter#find_or_create!` against `repository.review_stacks` — a plain `has_many` association that is not itself gated by the `review_stacks_enabled` boolean column: [3](#0-2) 

`ReviewStackAdapter#create!` runs to completion unconditionally — it creates the stack, builds/updates the `pull_request` association from the attacker-controlled payload, and queues the stack for provisioning: [4](#0-3) 

`ReviewStackProvisioningQueue.add` simply flips `awaiting_provision` on the stack: [5](#0-4) 

and the cron-driven queue worker later provisions any stack matching `awaiting_provision: true`, regardless of `review_stacks_enabled`: [6](#0-5) 

Nothing in this path — `params` schema validation, `Repository.from_github_repo_name`, model validations on `Repository`/`Stack`, or the queue worker — checks `review_stacks_enabled` at provisioning time; that flag is read only inside the buggy `provision?` expression. The attacker's exact action is: open a pull request (with no label) against a repository that Shipit already tracks with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false`. GitHub sends a legitimately signed `pull_request` "opened" webhook (satisfying `verify_signature`/`GitHubApp#verify_webhook_signature`, which this bug does not need to bypass), and the flawed boolean logic creates a `ReviewStack` and queues it for provisioning anyway, later running `TaskCommands#perform`/`deploy_spec.deploy_steps!` against the attacker's own `shipit.yml` in their branch.

Existing tests only exercise `prevent_with_label` with the default `review_stacks_enabled: true` (`configure_provisioning_behavior` defaults `provisioning_enabled: true`), so this specific combination is untested: [7](#0-6) 

### Impact Explanation
For any repository an operator has explicitly configured with `review_stacks_enabled: false` (intending to disable review-stack auto-provisioning entirely) but that still has `provisioning_behavior: prevent_with_label` set, any contributor able to open an unlabeled pull request can force Shipit to create a `ReviewStack`, run its provisioner, and execute the deploy steps from that PR's `shipit.yml` on the deploy host. This is unauthorized command execution on the deploy host driven entirely by attacker-controlled branch content, directly contradicting the operator's explicit intent to keep review stacks off for that repository. It is repeatable per PR/branch against any repository sharing this configuration.

### Likelihood Explanation
Requires an operator-configured combination (`review_stacks_enabled: false` + `provisioning_behavior: prevent_with_label`), which is a plausible/legitimate configuration choice for repositories wanting the label workflow purely to gate documentation while disabling other provisioning paths, or a misunderstanding-prone default. No secrets are needed by the attacker; only the ability to open a PR (unlabeled) against the tracked repository, which any contributor with PR rights (or via a public repo accepting PRs) has. Cost is a single PR open action.

### Recommendation
Fix operator precedence so `review_stacks_enabled` gates all three provisioning behaviors, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same audit to `LabeledHandler`, `UnlabeledHandler`, and `ReopenedHandler` since they share similar `provisioning_behavior_*` checks referencing `review_stacks_enabled`.

### Proof of Concept
```ruby
test "does not create stacks when review_stacks_enabled is false even with prevent_with_label and no label" do
  repository = shipit_repositories(:shipit)
  repository.update!(
    review_stacks_enabled: false,
    provisioning_behavior: :prevent_with_label,
    provisioning_label_name: "x"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  assert_equal false, repository.review_stacks_enabled

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Given the current code, this assertion fails: `Shipit::Stack.count` increases by 1, the created `ReviewStack` has `awaiting_provision: true`, and running `ReviewStackProvisioningQueue.work` subsequently invokes `stack.provision` → provisioner → deploy job executing `deploy_spec.deploy_steps!` from the PR's `shipit.yml`, despite `repository.review_stacks_enabled == false`.

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

**File:** app/models/shipit/repository.rb (L47-48)
```ruby
    has_many :stacks, dependent: :destroy
    has_many :review_stacks, dependent: :destroy
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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L9-11)
```ruby
    def self.add(stack)
      stack.enqueue_for_provisioning
    end
```

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L21-37)
```ruby
    def queued_stacks
      @queued_stacks ||= Shipit::ReviewStack
                         .with_provision_status(:deprovisioned)
                         .where(awaiting_provision: true)
    end

    private

    def provision(stack)
      if stack.provisioner.provision?
        stack.provision
      else
        Rails.logger.info(
          "Putting review ReviewStack<#{stack.id}> back into the provisioning queue - #provision? was falsey."
        )
      end
    end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L159-196)
```ruby
          test "create stacks for repos what prevent_with_label when label is absent" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] = []

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end

          test "does not create stacks for repos what prevent_with_label when label is present" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end

          def configure_provisioning_behavior(repository:, provisioning_enabled: true, behavior: :allow_all, label: nil)
            repository.review_stacks_enabled = provisioning_enabled
            repository.provisioning_behavior = behavior
            repository.provisioning_label_name = label
            repository.save!

            repository
          end
```
