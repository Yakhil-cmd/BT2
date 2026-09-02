### Title
Missing `review_stacks_enabled` guard on `allow_with_label`/`prevent_with_label` branches allows unauthorized `ReviewStack` creation - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` combines `repository.review_stacks_enabled` with the provisioning-behavior checks using `&&`/`||` in a way that, due to Ruby operator precedence, only gates the `allow_all` behavior on `review_stacks_enabled`. The `allow_with_label` and `prevent_with_label` clauses are evaluated independently of `review_stacks_enabled`, so a repository with review stacks disabled but `provisioning_behavior: allow_with_label` (or `prevent_with_label`) will still provision a `ReviewStack` when an attacker opens a PR with (or without) the matching label.

### Finding Description
The intended binding is: a `ReviewStack` should only ever be created when `repository.review_stacks_enabled == true`. The actual code is: [1](#0-0) 

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` has higher precedence than `||` in Ruby, this parses as:

```ruby
(repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?) ||
(repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
(repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```

`review_stacks_enabled` is ANDed only with the first clause (`allow_all?`); the other two clauses (`allow_with_label` and `prevent_with_label`) never reference `review_stacks_enabled` at all. Consequently, for a repository row with `review_stacks_enabled: false, provisioning_behavior: 'allow_with_label'`, `provision?` still returns `true` whenever the incoming PR carries the label named `repository.provisioning_label_name` (checked via `pull_request_has_provisioning_label?` at [2](#0-1) ).

The call chain is: `respond_to_pull_request_opened?` (line 60-63) → `provision?` returns true → `process` calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` at [3](#0-2)  → `find_or_create!`/`create!` at [4](#0-3)  and [5](#0-4)  unconditionally builds a new `Shipit::ReviewStack` with `branch: params.pull_request.head.ref` and `environment: "pr#{params.number}"`, with no re-check of `review_stacks_enabled` anywhere in `ReviewStackAdapter`.

No other guard exists in the reachable path: `Repository` model has no validation tying `provisioning_behavior` to `review_stacks_enabled` ( [6](#0-5) ), and `ProvisioningHandler::Base#provision?` (a separate, unrelated guard used later in the provisioning queue) defaults to `true` and doesn't reference `review_stacks_enabled` either ( [7](#0-6) ). The attacker only needs to open a PR from their own fork/branch with a label named after `provisioning_label_name` (a value the repo owner configured, but which is visible/guessable via UI/docs) against a repository that happens to have this specific misconfiguration.

### Impact Explanation
When triggered, an unprivileged PR author causes creation of a real `Shipit::ReviewStack` (and its provisioning queue entry) for a repository whose owner explicitly disabled review stacks. This is a record written for a repository that did not authorize/enable this feature, matching the "Critical" category of "a payload for one repository mutating another's stack" in spirit (here: mutating the same repository's stack table in a way its configuration explicitly forbids), and can lead to unwanted provisioning/deploy activity (`ReviewStackProvisioningQueue.add`) triggered by an untrusted branch/PR. It is repeatable against any repository sharing this specific configuration (`review_stacks_enabled: false` + `provisioning_behavior: allow_with_label` or `prevent_with_label`).

### Likelihood Explanation
Requires a specific repository configuration: `review_stacks_enabled: false` combined with `provisioning_behavior: 'allow_with_label'` (or `'prevent_with_label'`) — a plausible transitional/misconfigured state (e.g., an operator disables review stacks but leaves the provisioning behavior setting untouched). Attacker cost is trivial: open a PR and add a label. No secrets, sessions, or tokens are needed. This is not universal — it depends on that specific configuration combination existing — but is realistic given the settings UI allows independent toggling of these two fields ( [8](#0-7) , referenced indirectly).

### Recommendation
Fix operator precedence explicitly by parenthesizing the entire behavior check with `review_stacks_enabled`:

```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Apply the same fix pattern to `LabeledHandler`/`UnlabeledHandler`/`ReopenedHandler` if they contain the same `&&`/`||` construct (they reference `review_stacks_enabled` per the earlier grep results and should be checked for the identical precedence bug).

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):

```ruby
test "does not provision a review stack when review_stacks_enabled is false, even with allow_with_label + matching label" do
  repository = shipit_repositories(:shipit)
  repository.update!(
    review_stacks_enabled: false,
    provisioning_behavior: "allow_with_label",
    provisioning_label_name: "ship-it"
  )

  before_count = Shipit::ReviewStack.count

  # Binding under test: repository.review_stacks_enabled == false
  assert_equal false, repository.review_stacks_enabled

  params = build_opened_params(
    repository_full_name: repository.full_name,
    labels: [{ "name" => "ship-it" }]
  )
  Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(params).process

  # Expected (post-fix): no ReviewStack should be created
  assert_equal before_count, Shipit::ReviewStack.count,
    "ReviewStack was created despite review_stacks_enabled being false"
end
```

Before the fix, this assertion fails because `Shipit::ReviewStack.count` increments by 1, demonstrating that `provision?` returns `true` and `ReviewStackAdapter#create!` persists a `ReviewStack` for a repository with review stacks disabled.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L72-78)
```ruby
          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-21)
```ruby
          def find_or_create!
            stack || create!
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

**File:** app/models/shipit/repository.rb (L34-56)
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
```

**File:** app/models/shipit/provisioning_handler/base.rb (L18-23)
```ruby
      # An (optional) guard to prevent provisioning. Intended to be
      # use to set logic to determine if enough actual resources exist
      # to complete the provisioning request.
      def provision?
        true
      end
```

**File:** app/views/shipit/repositories/settings.html.erb (L1-2)
```erb
<%= render partial: 'shipit/repositories/header', locals: { repository: @repository } %>

```
