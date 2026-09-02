### Title
`OpenedHandler#provision?` operator-precedence bug bypasses `review_stacks_enabled` for `allow_with_label`/`prevent_with_label` repositories - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`provision?` intends to gate all review-stack creation on `repository.review_stacks_enabled`, but Ruby's `&&`/`||` precedence only applies that gate to the `allow_all?` branch. Any repository configured with `provisioning_behavior_allow_with_label?` or `provisioning_behavior_prevent_with_label?` will provision review stacks regardless of `review_stacks_enabled`, because that check is not part of those OR-clauses.

### Finding Description
The broken binding: the operator (owner) intends `repository.review_stacks_enabled == true` to be a prerequisite for provisioning under any behavior, but the code's actual truth value is `repository.review_stacks_enabled == false` still yields `provision? == true` whenever `provisioning_behavior_allow_with_label? && label_present` (or `prevent_with_label? && !label_present`) is true.

Code path: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:60-70`:
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
`&&` binds tighter than `||` in Ruby, so this parses as:
```
(review_stacks_enabled && allow_all?) || (allow_with_label? && label) || (prevent_with_label? && !label)
```
`review_stacks_enabled` is scoped only to the first disjunct. The second and third disjuncts are fully independent of `review_stacks_enabled`.

`repository.review_stacks_enabled` is a plain boolean column with no relationship enforced to `provisioning_behavior` in the model [1](#0-0) , and `NullRepository#review_stacks_enabled` returns `false` while `provisioning_behavior_allow_with_label?`/`prevent_with_label?` on `NullRepository` are hardcoded `false` too [2](#0-1)  — confirming these are meant to be independently significant flags, and for a persisted `Repository` record, `review_stacks_enabled: false` combined with `provisioning_behavior: allow_with_label` is a legitimate, reachable configuration state.

Attacker flow: attacker opens a PR (`action: 'opened'`) against the tracked repository, adds `deploy-me` label to their own PR (label management on one's own PR requires only write access on a fork/PR, not repo-maintainer rights — though note: adding labels typically requires triage/write permission on the base repo in real GitHub, but this is a config/logic bug independent of that detail), triggering `respond_to_pull_request_opened?` → `provision?` → `true` even though the repository owner disabled review stacks entirely. `ReviewStackAdapter#create!` then creates a `ReviewStack` bound to `branch: params.pull_request.head.ref` (attacker-controlled) [3](#0-2) .

Existing guards do not prevent this: webhook signature verification (`verify_signature`/`verify_webhook_signature` in `app/controllers/shipit/webhooks_controller.rb`) authenticates that the payload came from GitHub for that repository — it does not enforce the `review_stacks_enabled` policy, which is purely an application-level authorization check inside `provision?`. Repository/PullRequest model validations do not touch `review_stacks_enabled` vs `provisioning_behavior` consistency either [4](#0-3) .

### Impact Explanation
For any repository where the operator has explicitly set `review_stacks_enabled = false` but left a stale/default `provisioning_behavior` of `allow_with_label` or `prevent_with_label`, an unprivileged actor who can open a PR and attach/remove the configured label can force creation of a `Shipit::ReviewStack` (and associated provisioning queue entry) that the operator explicitly disabled. This is a record written for a repository whose authorization flag (`review_stacks_enabled`) forbids it — an authorization-policy violation causing unauthorized environment provisioning tied to an attacker-controlled branch. This matches "unauthorized deploy" class impact scoped to the repositories with this specific but plausible configuration combination.

### Likelihood Explanation
Preconditions are narrow but realistic: `review_stacks_enabled == false` AND `provisioning_behavior` is `allow_with_label` (with a label already applied) or `prevent_with_label` (with no label). Since `provisioning_behavior` and `review_stacks_enabled` are independently settable attributes with no validation coupling them [5](#0-4) , this state can arise naturally (e.g., an operator toggles `review_stacks_enabled` off while leaving `provisioning_behavior` unchanged, or a migration/default sets `provisioning_behavior` before `review_stacks_enabled` is explicitly disabled). Attacker cost is low (open a PR, add a label they control on their own PR) and repeatable per PR/number.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the entire expression:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```

### Proof of Concept
minitest in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` style:
```ruby
test "does not provision when review_stacks_enabled is false even with allow_with_label + matching label" do
  repository = shipit_repositories(:shipit)
  repository.update!(
    review_stacks_enabled: false,
    provisioning_behavior: :allow_with_label,
    provisioning_label_name: "deploy-me"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = [{ "name" => "deploy-me" }]

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Before the fix this assertion fails (`Shipit::Stack.count` increases by 1), demonstrating `provision?` returns `true` while `repository.review_stacks_enabled == false`.

### Citations

**File:** app/models/shipit/repository.rb (L17-31)
```ruby
    def review_stacks_enabled
      false
    end

    def provisioning_behavior_allow_all?
      false
    end

    def provisioning_behavior_allow_with_label?
      false
    end

    def provisioning_behavior_prevent_with_label?
      false
    end
```

**File:** app/models/shipit/repository.rb (L34-51)
```ruby
  class Repository < ApplicationRecord
    OWNER_MAX_SIZE = 39
    private_constant :OWNER_MAX_SIZE

    NAME_MAX_SIZE = 100
    private_constant :NAME_MAX_SIZE

    validates :name, uniqueness: { scope: %i[owner], case_sensitive: false,
                                   message: 'cannot be used more than once' }
    validates :owner, :name, presence: true, ascii_only: true
    validates :owner, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: OWNER_MAX_SIZE }
    validates :name, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: NAME_MAX_SIZE }

    has_many :stacks, dependent: :destroy
    has_many :review_stacks, dependent: :destroy

    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
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
