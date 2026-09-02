### Title
`OpenedHandler#provision?` operator-precedence bug lets `provisioning_behavior` bypass the `review_stacks_enabled` master switch - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` intends `review_stacks_enabled` to gate all dynamic-provisioning behaviors, but Ruby's `&&`/`||` precedence only scopes it to the `allow_all` branch. When a repository has `review_stacks_enabled = false` and `provisioning_behavior = allow_with_label` (or `prevent_with_label`), a PR carrying (or lacking) the configured label still triggers stack creation and enqueues provisioning, defeating the intended master switch.

### Finding Description
The claimed binding is: `review_stacks_enabled == false` implies `provision? == false` for every `provisioning_behavior` value. The actual code is: [1](#0-0) 

Because `&&` binds tighter than `||` in Ruby, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && label_present) || (prevent_with_label? && !label_present)`

`review_stacks_enabled` is only ANDed into the first disjunct. The second and third disjuncts — which cover `allow_with_label` and `prevent_with_label` — never reference `review_stacks_enabled` at all. So for those two behaviors, the value of `review_stacks_enabled` is completely irrelevant to the outcome.

Path: a genuine, signature-verified GitHub `pull_request` `opened` webhook (or `labeled`, same OR-chain in `LabeledHandler`/`ReopenedHandler`) is delivered for a tracked repository. `WebhooksController` verifies the HMAC signature via `GitHubApp#verify_webhook_signature` [2](#0-1) , so the payload must originate from GitHub for a repo whose webhook is registered with Shipit — this does not block the bug, it only requires the attacker's own repository (or a repo they can label PRs on) to already be tracked by Shipit with a real webhook, which is the normal onboarding state. `OpenedHandler#process` calls `respond_to_pull_request_opened?` → `provision?` [3](#0-2) ; if it evaluates true, `ReviewStackAdapter#find_or_create!` creates a `Shipit::ReviewStack` and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` [4](#0-3) , which later invokes the host application's `ProvisioningHandler#up` to allocate real infrastructure.

Exploit flow: an operator sets `review_stacks_enabled = false` intending to fully disable review-stack provisioning, but leaves `provisioning_behavior = allow_with_label` (or `prevent_with_label`) with a residual/stale `provisioning_label_name` from prior use — a state reachable purely via independent column updates (settings form or API), with no code enforcing `review_stacks_enabled` as a true master switch. An attacker who can add the configured label to a PR on that repository (or, for `prevent_with_label`, simply avoid adding it) causes `provision?` to return true despite `review_stacks_enabled == false`, resulting in unauthorized stack creation and provisioning-handler invocation.

No existing guard catches this: webhook signature verification only authenticates the source repo/payload, not this authorization logic; `ExplicitParameters` validates payload shape, not behavior; there is no model validation tying `provisioning_behavior` to `review_stacks_enabled` in `Shipit::Repository` [5](#0-4) . Existing tests never exercise `provisioning_enabled: false` combined with `allow_with_label`/`prevent_with_label` and a matching label state [6](#0-5) , so the gap is untested and unnoticed.

### Impact Explanation
For the affected repository (one whose operator disabled `review_stacks_enabled` but left a stale `allow_with_label`/`prevent_with_label` setting), an attacker able to label their own PR causes Shipit to create a `Shipit::ReviewStack` and invoke the host's `ProvisioningHandler#up`, i.e., unauthorized infrastructure provisioning/resource allocation that the operator believed was disabled. Impact is scoped to that single misconfigured repository (no cross-tenant mutation), and is repeatable on every PR open/label/reopen event against it. This matches the "unauthorized deploy/provisioning action" class of impact rather than RCE or credential exfiltration.

### Likelihood Explanation
Requires a specific but plausible misconfiguration: `review_stacks_enabled=false` with `provisioning_behavior` still `allow_with_label` or `prevent_with_label` and a live `provisioning_label_name`. This is achievable by an operator toggling the checkbox off without resetting the dropdown, or via independent field updates (the UI form submits all three fields together via `form_for @repository`, but nothing prevents partial/independent updates through direct model access or future API endpoints). Attacker cost is low (label a PR they control) once this configuration state exists; it is not exploitable against a "cleanly disabled" repository where `provisioning_behavior` was also reset to a state that requires the flag.

### Recommendation
Add explicit parentheses/grouping so `review_stacks_enabled` gates the entire expression:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Apply the same fix to the identical OR-chain in `ReopenedHandler#unarchive?` and `LabeledHandler`/`UnlabeledHandler` equivalents.

### Proof of Concept
Add a minitest exhaustively enumerating `(review_stacks_enabled, provisioning_behavior, label_present)`:
```ruby
test "review_stacks_enabled must gate every provisioning_behavior" do
  [true, false].each do |enabled|
    %i[allow_all allow_with_label prevent_with_label].each do |behavior|
      [true, false].each do |label_present|
        repository = shipit_repositories(:shipit)
        repository.update!(
          review_stacks_enabled: enabled,
          provisioning_behavior: behavior,
          provisioning_label_name: "pull-requests-label"
        )
        payload = payload_parsed(:pull_request_opened)
        payload["pull_request"]["labels"] =
          label_present ? [{ "name" => "pull-requests-label" }] : []

        expected = enabled && (
          behavior == :allow_all ||
          (behavior == :allow_with_label && label_present) ||
          (behavior == :prevent_with_label && !label_present)
        )

        if expected
          assert_difference -> { Shipit::Stack.count }, 1 do
            OpenedHandler.new(payload).process
          end
        else
          assert_no_difference -> { Shipit::Stack.count } do
            OpenedHandler.new(payload).process
          end
        end
      end
    end
  end
end
```
This fails on current code for `enabled=false, behavior=:allow_with_label, label_present=true` (and `enabled=false, behavior=:prevent_with_label, label_present=false`), since `provision?` returns true even though `review_stacks_enabled` is false.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L1-1)
```ruby
# frozen_string_literal: true
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
