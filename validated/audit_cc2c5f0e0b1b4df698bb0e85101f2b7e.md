### Title
`OpenedHandler#provision?` / `ReopenedHandler#unarchive?` bypass `review_stacks_enabled` for `allow_with_label`/`prevent_with_label` due to `&&`/`||` operator precedence - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`Repository#provisioning_behavior_allow_with_label?` / `#provisioning_behavior_prevent_with_label?` are plain enum predicates with no dependency on `review_stacks_enabled`, so the invariant "provisioning behavior implies review stacks enabled" must be enforced by callers. `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` attempt to enforce it but fail because Ruby's `&&` binds tighter than `||`, so `review_stacks_enabled` only gates the `allow_all?` branch, not the `allow_with_label?`/`prevent_with_label?` branches.

### Finding Description
The broken binding: `repository.provisioning_behavior_allow_with_label?` (or `prevent_with_label?`) being true should imply `repository.review_stacks_enabled == true` before a PR can trigger review-stack creation, but the code does not enforce this equality on two of the three branches.

`provision?` in `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`: [1](#0-0) 

is parsed by Ruby as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)` because `&&` has higher precedence than `||`. `review_stacks_enabled` is therefore only ANDed into the first disjunct; the second and third disjuncts (`allow_with_label?`/`prevent_with_label?`) are evaluated purely from the `provisioning_behavior` enum column, independent of `review_stacks_enabled`. `ReopenedHandler#unarchive?` has the identical bug: [2](#0-1) 

By contrast, `LabeledHandler#respond_to_label_change?` and `UnlabeledHandler#respond_to_label_change?` correctly gate the entire decision on `review_stacks_enabled` as a separate top-level `&&` term wrapped around the whole disjunction: [3](#0-2) [4](#0-3)  — proving the intended invariant and confirming `opened_handler.rb`/`reopened_handler.rb` diverge from it due to a precedence mistake.

The `Repository` model itself enforces nothing: [5](#0-4)  defines the enum with no validation tying it to `review_stacks_enabled`, and no scope/validation exists anywhere in the class [6](#0-5) .

Exploit flow: if an operator sets `review_stacks_enabled=false` on a repository while leaving `provisioning_behavior=allow_with_label` (or `prevent_with_label`) set (e.g., after temporarily disabling review stacks, or before fully wiring up the feature), any unauthenticated attacker who can open a pull request on that repository and apply/omit a label (their own PR, their own label, no privileged token needed) can still trigger `OpenedHandler#process` to call `ReviewStackAdapter#find_or_create!`, which calls `create!` to persist a new `Shipit::ReviewStack`, build its `pull_request`, and enqueue it via `Shipit::ReviewStackProvisioningQueue.add(stack)` [7](#0-6)  — despite the operator's explicit intent that review stacks be disabled for that repository. Reopening a PR similarly reaches `stack.unarchive!`, re-enqueuing provisioning [8](#0-7) .

`verify_signature`/webhook signature checks are irrelevant here: this is not a forged-webhook attack, it is a logic bug reachable through a legitimately signed webhook from the attacker's own repository/PR activity, so those guards do not prevent the divergence. No validation on `Repository` prevents `review_stacks_enabled=false` with `provisioning_behavior` set to a non-default value.

### Impact Explanation
For a misconfigured repository (`review_stacks_enabled=false`, `provisioning_behavior` != `allow_all`... specifically `allow_with_label`/`prevent_with_label`), an attacker who can open/label/reopen a PR causes Shipit to create and provision a review stack (a real deploy/build resource) for that repository against the operator's explicit configuration. This is a repeatable, per-PR bypass of an authorization/configuration gate that the engine's own `LabeledHandler`/`UnlabeledHandler` code proves was intended to be enforced. It matches "an unauthorized deploy" / record-written-without-authorization impact, scoped to repositories in this specific misconfigured state — it does not cross tenant/repository boundaries beyond the affected repo itself.

### Likelihood Explanation
Requires the specific precondition that a repository has `review_stacks_enabled=false` while `provisioning_behavior` is `allow_with_label` or `prevent_with_label` — a configuration state the engine allows because no validation prevents it. If that state exists, exploitation is trivial and free for the attacker (open a PR, optionally add a label) and fully repeatable for every PR on that repository. Likelihood is contingent on operator misconfiguration but the engine provides zero defense-in-depth against it, which is the crux of the audit question.

### Recommendation
Fix operator precedence in `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` by parenthesizing so `review_stacks_enabled` gates the entire expression, matching `LabeledHandler`/`UnlabeledHandler`:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Additionally, add a model-level invariant on `Shipit::Repository` (e.g., a validation or normalizing default) ensuring `provisioning_behavior` cannot be non-default while `review_stacks_enabled` is false, so callers cannot regress this again.

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` (test dir out of scope for delivery but describing the plan):
1. Build a `Repository` with `review_stacks_enabled: false, provisioning_behavior: "allow_with_label"`.
2. Assert the broken binding directly: `repository.provisioning_behavior_allow_with_label?` returns `true` while `repository.review_stacks_enabled` is `false` — no validation error is raised on `repository.valid?`.
3. Construct `OpenedHandler` params with `action: "opened"` and a PR carrying the repository's `provisioning_label_name` label.
4. Call `handler.process` and assert a `Shipit::ReviewStack` is created (`repository.review_stacks.count` goes from 0 to 1) even though `review_stacks_enabled` is `false`, proving the authorization gap.
5. Repeat with `provisioning_behavior: "prevent_with_label"` and no label present, expecting the same erroneous creation.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L79-84)
```ruby
          def respond_to_label_change?
            params.action == "unlabeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```

**File:** app/models/shipit/repository.rb (L34-103)
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

    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end

    def name=(name_value)
      super(name_value&.downcase)
    end

    def owner=(owner_value)
      super(owner_value&.downcase)
    end

    def github_repo_name
      [owner, name].join('/')
    end

    def http_url
      github_app.url(full_name)
    end

    def full_name
      "#{owner}/#{name}"
    end

    def git_url
      "https://#{github_app.domain}/#{owner}/#{name}.git"
    end

    def schedule_for_destroy!
      DestroyRepositoryJob.perform_later(self)
    end

    def to_param
      github_repo_name
    end

    def self.from_param!(param)
      repo_owner, repo_name = param.split('/')
      where(
        owner: repo_owner.downcase,
        name: repo_name.downcase
      ).first!
    end

    protected

    def github_app
      Shipit.github(organization: owner)
    end
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
