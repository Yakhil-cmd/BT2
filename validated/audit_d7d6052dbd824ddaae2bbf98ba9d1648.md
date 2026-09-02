### Title
`ReopenedHandler#unarchive?` operator-precedence bug lets label-based provisioning bypass `review_stacks_enabled` - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler#unarchive?` (and the identical pattern in `OpenedHandler#provision?`) intends `review_stacks_enabled` to gate all review-stack provisioning, but Ruby's `&&`/`||` precedence makes `review_stacks_enabled` only apply to the `allow_all?` branch. When a repository has `review_stacks_enabled = false` but `provisioning_behavior` set to `allow_with_label` or `prevent_with_label`, an attacker who can label their own PR can still trigger stack creation/unarchival and enqueue it into `Shipit::ReviewStackProvisioningQueue`, which the `cron:minutely` task provisions unconditionally.

### Finding Description
The intended binding is:
`unarchive? == repository.review_stacks_enabled && (allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?))`

The actual code is:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Because `&&` binds tighter than `||`, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

`review_stacks_enabled` is not distributed to the second and third disjuncts, so when `review_stacks_enabled == false` and `provisioning_behavior` is `allow_with_label` (or `prevent_with_label`), `unarchive?` still evaluates `true` purely based on the PR's label state — a value the attacker (PR author on their own PR/fork) fully controls, per `pull_request_has_provisioning_label?`. [2](#0-1) 

The identical faulty pattern also exists in `OpenedHandler#provision?`, confirming this is a systemic logic bug rather than an isolated typo. [3](#0-2) 

Verification that no other guard rescues this: `review_stacks_enabled` and `provisioning_behavior` are independent columns on `Shipit::Repository` with no model validation tying them together — nothing forces `provisioning_behavior` to a non-label value when `review_stacks_enabled` is false. [4](#0-3) 

Exploit flow: attacker reopens a PR against a repository configured with `review_stacks_enabled = false` and `provisioning_behavior = allow_with_label`, applies the provisioning label to their own PR, and sends the `reopened` webhook (label state is read from the payload's `pull_request.labels`, fully attacker-supplied). `respond_to_pull_request_reopened?` calls `unarchive?`, which returns `true` despite `review_stacks_enabled` being `false`, and `stack.unarchive!`/`ReviewStackAdapter#create!` enqueues the stack via `Shipit::ReviewStackProvisioningQueue.add(stack)`. [5](#0-4)  `cron:minutely` then unconditionally runs `Shipit::ReviewStackProvisioningQueue.work`, which provisions any queued stack with no re-check of `review_stacks_enabled`. [6](#0-5) 

### Impact Explanation
An attacker who owns a PR against a repository with this specific (but plausible) configuration mismatch — `review_stacks_enabled=false` combined with a label-based `provisioning_behavior` — can force creation/unarchival and subsequent provisioning of a review stack that the repository owner explicitly intended to disable. This is a write (stack creation, provisioning queue entry) performed for a repository configuration that did not authorize it, matching the "unauthorized deploy" / authorization-bypass category. The blast radius is scoped to repositories with this specific configuration; it does not cross tenant boundaries into unrelated repositories, but within an affected repository it fully defeats the `review_stacks_enabled` kill-switch.

### Likelihood Explanation
Exploitability strictly requires the target repository to be configured with `review_stacks_enabled = false` and `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` — a state that is easy to create (e.g., an operator disables review stacks but leaves the previously-configured provisioning behavior untouched, since the two settings are independent and nothing prevents this combination). Given that configuration, the attacker cost is trivial: label their own PR and reopen it (or open it, for the `OpenedHandler` variant) — no secrets, tokens, or privileged roles required, fully repeatable per PR/label toggle.

### Recommendation
Fix operator precedence to correctly distribute `review_stacks_enabled` across all disjuncts, e.g.:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to `OpenedHandler#provision?`.

### Proof of Concept
Minitest plan (in `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`, not part of this audit's fix but describing the reproducible assertion):
1. Create a `Shipit::Repository` with `review_stacks_enabled: false`, `provisioning_behavior: "allow_with_label"`.
2. Build a `reopened` webhook payload where `pull_request.labels` includes the repository's `provisioning_label_name`, `pull_request.state == "open"`.
3. Instantiate `ReopenedHandler` with these params and call `#process`.
4. Assert LHS `repository.review_stacks_enabled == false` and RHS `handler.send(:unarchive?) == true` — the mismatch demonstrates the broken binding.
5. Assert `Shipit::ReviewStack.exists?(environment: "pr#{number}")` is `true` and that a row was added to `Shipit::ReviewStackProvisioningQueue`, proving unauthorized provisioning occurred despite `review_stacks_enabled == false`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L77-83)
```ruby
          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
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

**File:** lib/tasks/cron.rake (L5-12)
```text
  task minutely: :environment do
    Shipit::Stack.refresh_deployed_revisions
    Shipit::Stack.schedule_continuous_delivery
    Shipit::GithubStatus.refresh_status
    Shipit::MergeRequest.schedule_merges
    Shipit::ReapDeadTasksJob.perform_later
    Shipit::ReviewStackProvisioningQueue.work
  end
```
