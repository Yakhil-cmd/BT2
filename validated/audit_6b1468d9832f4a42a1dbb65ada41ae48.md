Confirmed: `review_stacks_enabled` defaults to `false` on the `repositories` table [1](#0-0) , while `provisioning_behavior` defaults to `"allow_all"` [2](#0-1) . The `OpenedHandler#provision?` predicate has an operator-precedence bug that only gates the `allow_all` behavior on `review_stacks_enabled`, not the other two behaviors: [3](#0-2) 

Because `&&` binds tighter than `||` in Ruby, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. `review_stacks_enabled` is not applied to the `allow_with_label`/`prevent_with_label` branches at all.

### Title
`OpenedHandler#provision?` operator-precedence bug bypasses `review_stacks_enabled` gate for `allow_with_label`/`prevent_with_label` repositories - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`OpenedHandler#provision?` mixes `&&`/`||` without parentheses, so `review_stacks_enabled` only gates the `allow_all` provisioning behavior; it is silently ignored for `allow_with_label` and `prevent_with_label` behaviors. If an operator ever sets `provisioning_behavior` to one of those two values while leaving (or resetting) `review_stacks_enabled` to its default `false`, any PR author can trigger `ReviewStackAdapter#find_or_create!` → `create!` → `Shipit::ReviewStackProvisioningQueue.add(stack)`, eventually reaching `PTY.spawn` with `GITHUB_TOKEN`/`GIT_ASKPASS` in the process environment.

### Finding Description
Binding claimed: the ref whose `shipit.yml` supplies executed steps == a ref an authorized user approved via `review_stacks_enabled = true`. The code as written does not enforce this equality for two of the three provisioning-behavior modes.

`provision?` is:
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [3](#0-2) 

Ruby precedence groups this as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. The `review_stacks_enabled` check is scoped only to the first disjunct. If `repository.provisioning_behavior` is `"allow_with_label"` or `"prevent_with_label"` (either intentionally set for another purpose, or left at a non-default value with `review_stacks_enabled` still `false`), `provision?` returns `true` even though the operator never enabled review stacks.

`process` calls this unguarded predicate: `return unless respond_to_pull_request_opened?` then `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` [4](#0-3) . `find_or_create!` calls `create!`, which persists a new `ReviewStack` from `params.pull_request.head.ref` and enqueues it: `Shipit::ReviewStackProvisioningQueue.add(stack)` [5](#0-4) . This queue entry is later dequeued for provisioning, ultimately running `shipit.yml` from the attacker-controlled ref through `Command`/`PTY.spawn`.

Attacker exploit flow: attacker opens a PR against a repository whose maintainer configured `provisioning_behavior: allow_with_label` (e.g., to gate a totally different feature, or before ever toggling `review_stacks_enabled` on) and applies the configured label to their own PR (`labels` array is attacker-controlled in the `opened` webhook payload, per `PullRequest#labels`). Because `review_stacks_enabled` defaults to `false` and is not checked on this branch, `provision?` still returns `true`, and a stack is provisioned from the attacker's fork/branch.

Existing guards do not prevent this: `verify_signature`/webhook auth only ensures the payload came from GitHub for that repo, not that provisioning was authorized [6](#0-5) ; there is no separate check re-validating `review_stacks_enabled` inside `ReviewStackAdapter#create!` [5](#0-4) .

Note: I could not fully confirm from the index whether any downstream migration or model callback forces `provisioning_behavior` back to `allow_all` whenever `review_stacks_enabled` is `false` (which would neutralize this), nor whether the `repositories_controller`/settings view enforces that these two fields are only ever set together. Available code (`Repository` model and settings view) shows no such coupling [7](#0-6) .

### Impact Explanation
If a repository is left in (or reverted to) `review_stacks_enabled: false` with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (both plausible transient/misconfiguration states, since these are independent DB columns with independent defaults), any external PR author can force stack creation and provisioning-queue enqueue for that repository, without operator approval of review-stack functionality being currently in effect. This leads to `shipit.yml` from an attacker-influenced ref being executed via `Command#start`/`PTY.spawn` with `GITHUB_TOKEN`/`GIT_ASKPASS` in the environment — Critical (RCE on the deploy host). It is repeatable against any repository misconfigured this way, and each PR/label toggle can re-trigger unarchive/provision cycles.

### Likelihood Explanation
This does not fire on a repository at its pure defaults with no behavior ever configured, because `provisioning_behavior` also defaults to `allow_all`, which correctly is gated by `review_stacks_enabled`. The exploit requires the operator's `provisioning_behavior` column to be `allow_with_label` or `prevent_with_label` while `review_stacks_enabled` is `false` — a state reachable simply by an operator toggling `review_stacks_enabled` off after having configured a label-based behavior (a very plausible "disable review stacks" action, since there is no code path resetting `provisioning_behavior` when disabling), or by any settings flow that sets these fields independently. Given `repositories_controller.rb` and the settings view expose `review_stacks_enabled` and `provisioning_behavior` as independent form fields [8](#0-7) , this is a realistic misconfiguration, not a contrived edge case. Attacker cost is a single PR + label, fully within the unprivileged attacker's capability (PR authors can set labels on their own PR in the webhook payload processing here — actual GitHub label permissions aren't rechecked by this handler, it trusts the payload's `labels` array).

### Recommendation
Parenthesize `provision?` to apply `repository.review_stacks_enabled` to all three branches:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Apply the same audit to `reopened_handler.rb`'s `unarchive?`, which has the identical precedence pattern [9](#0-8) .

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb
test "does NOT create stacks when review_stacks_enabled is false, even with allow_with_label + matching label" do
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :allow_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = [{ "name" => "pull-requests-label" }]

  Shipit::ReviewStackProvisioningQueue.expects(:add).never
  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Binding assertion: `repository.review_stacks_enabled` (== `false`, no operator approval) must equal the effective gate applied in `provision?` before any `ReviewStackProvisioningQueue.add` call is made. Currently this test fails against the shown code because `provision?` returns `true` and `ReviewStackProvisioningQueue.add` fires, demonstrating the divergence.

### Citations

**File:** db/migrate/20201001125502_add_provision_pr_stacks_flag_to_repositories.rb (L1-6)
```ruby
class AddProvisionPrStacksFlagToRepositories < ActiveRecord::Migration[6.0]
  def change
    add_column :repositories, :review_stacks_enabled, :boolean, default: false
    add_column :repositories, :provisioning_behavior, :string, default: :allow_all
    add_column :repositories, :provisioning_label_name, :string
  end
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

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

**File:** app/controllers/shipit/repositories_controller.rb (L1-1)
```ruby
# frozen_string_literal: true
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
