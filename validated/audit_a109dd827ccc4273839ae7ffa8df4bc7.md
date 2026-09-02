### Title
`OpenedHandler#provision?` operator-precedence bug lets `provisioning_behavior_allow_with_label?`/`prevent_with_label?` bypass `review_stacks_enabled` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`provision?` is written as `repository.review_stacks_enabled && repository.provisioning_behavior_allow_all? || (...) || (...)`. Because Ruby's `&&` binds tighter than `||`, the `review_stacks_enabled` flag is ANDed only with the `allow_all?` branch, not with the `allow_with_label?`/`prevent_with_label?` branches. This means an operator who unchecks "Dynamically provision stacks for Pull Requests?" but has `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` still gets stacks auto-provisioned for matching PRs, including from unprivileged fork PRs.

### Finding Description
The intended binding is: `review_stacks_enabled == true` should be a precondition for provisioning under **any** behavior, i.e. `provision? == review_stacks_enabled && (allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?))`.

The actual code at [1](#0-0)  parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

so when `review_stacks_enabled == false` but `provisioning_behavior == "allow_with_label"` and the PR carries the configured label (`provisioning_label_name`), `provision?` still returns `true`. The label check itself is fully attacker-controlled: `pull_request_has_provisioning_label?` inspects `pull_request["labels"]`, which any PR author can set on their own PR [2](#0-1) .

Once `provision?` is true, `process` calls `ReviewStackAdapter#find_or_create!` → `create!`, which sets `stack_attributes[:branch] = params.pull_request.head.ref` directly from the incoming webhook payload with no validation that the ref belongs to the base repo or was approved by a maintainer [3](#0-2) . The stack is then queued via `Shipit::ReviewStackProvisioningQueue.add(stack)` for provisioning, which downstream reads `shipit.yml`/deploy steps from that branch and executes them.

Existing guards do not catch this: `respond_to_pull_request_opened?` only checks `params.action == "opened"` and `provision?` [4](#0-3) ; there is no additional check that `review_stacks_enabled` gates all behaviors. The existing test suite only verifies the `allow_all?` + `review_stacks_enabled: false` combination is blocked [5](#0-4) ; there is no test for `allow_with_label`/`prevent_with_label` combined with `review_stacks_enabled: false`, confirming the gap is unguarded.

### Impact Explanation
For any repository where an operator has set `provisioning_behavior` to `allow_with_label` (or `prevent_with_label`) while believing `review_stacks_enabled = false` fully disables auto-provisioning, an unprivileged fork owner can open a labeled PR and force Shipit to create and provision a `ReviewStack` whose `branch` is the attacker's own fork ref. This is repeatable per PR/per repository matching this configuration and leads into the same downstream chain (`TaskCommands#perform` → `DeploySpec::FileSystem` → `Command#start` → `PTY.spawn`) that executes attacker-supplied `shipit.yml` steps with `GITHUB_TOKEN`/`GIT_ASKPASS` in the environment — matching the Critical "unauthorized deploy" / RCE-via-`Command`/`PTY.spawn` category, since a stack gets provisioned and its steps executed for a ref that was never approved by an authorized user.

### Likelihood Explanation
Requires a specific but plausible repository misconfiguration: `provisioning_behavior` set to `allow_with_label` (or `prevent_with_label`) with a `provisioning_label_name` configured, while `review_stacks_enabled` is left/set to `false` (e.g., an operator toggling the "master switch" without realizing it doesn't fully disable label-driven behaviors). Given `review_stacks_enabled` defaults to `false` and `provisioning_behavior` defaults to `allow_all` per the migration [6](#0-5) , this requires the operator to have explicitly changed `provisioning_behavior` away from the default while leaving/toggling `review_stacks_enabled` off — a state the settings UI's own help text does nothing to warn against [7](#0-6) . Once that configuration exists, exploitation is trivial and free for any GitHub user who can open a PR and add a label to it.

### Recommendation
Fix the operator precedence in `provision?` so `review_stacks_enabled` gates all three behaviors:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
Minitest plan (extends `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
1. `configure_provisioning_behavior(repository:, provisioning_enabled: false, behavior: :allow_with_label, label: "pull-requests-label")`.
2. Build `payload = payload_parsed(:pull_request_opened)`, append `{"name" => "pull-requests-label"}` to `payload["pull_request"]["labels"]`.
3. Assert binding before fix: `assert_difference -> { Shipit::Stack.count } do OpenedHandler.new(payload).process end` — this currently passes (stack created), proving `review_stacks_enabled == false` did **not** equal "no provisioning occurs".
4. After applying the fix, assert `assert_no_difference -> { Shipit::Stack.count } do OpenedHandler.new(payload).process end`.
5. Additionally assert on the created stack (pre-fix) that `stack.branch == payload["pull_request"]["head"]["ref"]` with no operator-approval record present, confirming the branch used for provisioning is fully attacker-controlled.

### Citations

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

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L96-107)
```ruby
          test "only provision stacks for repos with auto-provisioning enabled" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              provisioning_enabled: false,
              behavior: :allow_all
            )

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload_parsed(:provision_disabled_pull_request)).process
            end
          end
```

**File:** db/migrate/20201001125502_add_provision_pr_stacks_flag_to_repositories.rb (L1-6)
```ruby
class AddProvisionPrStacksFlagToRepositories < ActiveRecord::Migration[6.0]
  def change
    add_column :repositories, :review_stacks_enabled, :boolean, default: false
    add_column :repositories, :provisioning_behavior, :string, default: :allow_all
    add_column :repositories, :provisioning_label_name, :string
  end
```

**File:** app/views/shipit/repositories/settings.html.erb (L9-41)
```erb
    <div class="setting-section">
      <%= form_for @repository do |f| %>
        <div class="field-wrapper">
          <%= f.check_box :review_stacks_enabled %>
          <%= f.label :review_stacks_enabled, "Dynamically provision stacks for Pull Requests?" %>
        </div>

        <div class="field-wrapper">
          <p>
            <%= f.label :provisioning_behavior, "Provisioning behavior", aria: { describedby: 'provisioningBehaviorHelp' } %>
            <%= f.select :provisioning_behavior, Shipit::Repository.provisioning_behaviors.map { |key, value| [ key.titleize, key] } %>
          </p>
          <p>
            <small class="form-text text-muted" id="provisioningBehaviorHelp">
              When "Allow All", the provisioning label has no effect on dynamic stack provisioning - ALL Pull Requests dynamically provision stacks.
            </small>
          </p>
          <p>
            <small class="form-text text-muted">
              When "Allow With Label", dynamic provisioning occurs ONLY for Pull Requests whose labels include the 'Provisioning Label'.
            </small>
          </p>
          <p>
            <small class="form-text text-muted">
              When "Prevent With Label", dynamic provisioning will occur for every Pull Request EXCEPT those whose labels include the 'Provisioning Label'.
            </small>
          </p>
        </div>

        <div class="field-wrapper">
          <%= f.label :provisioning_label_name, "Provisioning label" %>
          <%= f.text_field :provisioning_label_name %>
        </div>
```
