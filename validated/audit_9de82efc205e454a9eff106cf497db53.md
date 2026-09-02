### Title
`OpenedHandler#provision?` bypasses `review_stacks_enabled` via `&&`/`||` operator precedence, allowing provisioning while disabled - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` is intended to gate all dynamic review-stack provisioning behind `repository.review_stacks_enabled`, but Ruby's operator precedence (`&&` binds tighter than `||`) makes that gate apply only to the `allow_all` branch. When a repository's `provisioning_behavior` is `allow_with_label` or `prevent_with_label`, `provision?` returns `true` and `Shipit::ReviewStackProvisioningQueue.add` is invoked even if the owner explicitly set `review_stacks_enabled` to `false`.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == true` must hold whenever `Shipit::ReviewStackProvisioningQueue.add(stack)` is reached from `OpenedHandler#process`.

The gate is implemented as: [1](#0-0) 

Parsed with Ruby precedence, this is actually:
`(review_stacks_enabled && provisioning_behavior_allow_all?) || (provisioning_behavior_allow_with_label? && has_label?) || (provisioning_behavior_prevent_with_label? && !has_label?)`

`review_stacks_enabled` is therefore only consulted for the `allow_all` branch; the `allow_with_label` and `prevent_with_label` branches are entirely independent of it. `review_stacks_enabled` (boolean, default `false`) and `provisioning_behavior` (enum, default `"allow_all"`) are independent columns set via two unrelated form fields with no cross-field validation: [2](#0-1) [3](#0-2) 

So a repository owner can legitimately reach the state `review_stacks_enabled: false, provisioning_behavior: "prevent_with_label"` (e.g., previously used labeled provisioning, then unchecked "Dynamically provision stacks" without also resetting the behavior dropdown back to allow_all). In that state, `respond_to_pull_request_opened?` → `provision?` still evaluates `true` for any opened PR that lacks the provisioning label — which is the default state for any external contributor's PR, since adding the label typically requires collaborator/maintainer status. `process` then calls `ReviewStackAdapter#find_or_create!` → `create!`, which unconditionally calls `Shipit::ReviewStackProvisioningQueue.add(stack)`: [4](#0-3) 

No other guard (`verify_signature`, `ExplicitParameters` schema, `drop_unhandled_event`) checks `review_stacks_enabled` at all — that check exists solely inside `provision?`, and the precedence bug neutralizes it for two of the three `provisioning_behavior` values. The same defective pattern is duplicated in `ReopenedHandler#unarchive?`: [5](#0-4) 

Existing tests never exercise `review_stacks_enabled: false` combined with `allow_with_label`/`prevent_with_label`, so this gap is untested: [6](#0-5) 

Attacker's request: open a pull request (`action: "opened"` webhook, `POST /webhooks`) against a tracked repository whose owner set `review_stacks_enabled = false` but left/set `provisioning_behavior = prevent_with_label` (or `allow_with_label` with the label already present, e.g. auto-applied by a bot/label-sync workflow). No special permission is required to open a PR.

### Impact Explanation
For any repository configured with `review_stacks_enabled: false` + `provisioning_behavior: prevent_with_label` (or `allow_with_label` + label present), any unprivileged GitHub user who can open a pull request against that repository causes Shipit to create a `ReviewStack` record and enqueue it via `Shipit::ReviewStackProvisioningQueue.add`, leading to unauthorized deploy/task execution against that repository's environment — directly contradicting the owner's explicit intent to disable review-stack auto-provisioning. This is repeatable per-PR and affects any tenant repository that reaches this specific (but easily reachable) configuration combination. This matches the Critical category ("a payload for one repository mutating another's stack... or an unauthorized deploy, rollback or merge") in that it results in an unauthorized deploy/task execution against a repository's stack list, contrary to explicit operator configuration.

### Likelihood Explanation
Requires the repository to be in the specific state `review_stacks_enabled: false` with `provisioning_behavior` other than `allow_all` — a state reachable through normal, legitimate use of the settings UI shown above (fields are independent, no validation enforces consistency), and plausible when an operator disables review stacks after previously using labeled provisioning. Once in that state, the attacker only needs to open (or leave open) a pull request, at zero cost and fully repeatable.

### Recommendation
Add explicit parentheses to `provision?` (and the identical `unarchive?` in `ReopenedHandler`) so `review_stacks_enabled` gates all branches:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

### Proof of Concept
minitest plan (in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` style):
```ruby
test "does not provision when review_stacks_enabled is false, even with prevent_with_label and no label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  assert_equal false, repository.reload.review_stacks_enabled
  Shipit::ReviewStackProvisioningQueue.expects(:add).never

  OpenedHandler.new(payload).process
end

test "does not provision when review_stacks_enabled is false, even with allow_with_label and label present" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_equal false, repository.reload.review_stacks_enabled
  Shipit::ReviewStackProvisioningQueue.expects(:add).never

  OpenedHandler.new(payload).process
end
```
Both assertions on `repository.review_stacks_enabled == false` (left side of the binding) and `ReviewStackProvisioningQueue.add` never being called (right side, representing "no provisioning occurred") should hold together; with the current code, the second assertion fails because `add` is called despite `review_stacks_enabled` being `false`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/views/shipit/repositories/settings.html.erb (L10-41)
```erb
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

**File:** test/dummy/db/schema.rb (L250-259)
```ruby
  create_table "repositories", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "name", limit: 100, null: false
    t.string "owner", limit: 39, null: false
    t.string "provisioning_behavior", default: "allow_all"
    t.string "provisioning_label_name"
    t.boolean "review_stacks_enabled", default: false
    t.datetime "updated_at", null: false
    t.index ["owner", "name"], name: "repository_unicity", unique: true
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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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
