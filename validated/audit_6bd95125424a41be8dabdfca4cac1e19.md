### Title
`OpenedHandler#provision?` ignores `review_stacks_enabled` for the `allow_with_label`/`prevent_with_label` branches due to operator precedence - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:65-69)

### Summary
The claimed binding `review_stacks_enabled == true` gating all review-stack auto-provisioning is broken by Ruby operator precedence: `&&` binds tighter than `||`, so `review_stacks_enabled` is only ANDed into the first disjunct (`allow_all?`), not the other two. An attacker who can label their own pull request can force `provision?` to return `true` and get a `ReviewStack` created and queued for provisioning even when the operator set `review_stacks_enabled: false`.

### Finding Description
Intended binding: `review_stacks_enabled == (provision? true requires operator's opt-in)`, i.e. `provision?` should equal `review_stacks_enabled && (allow_all? || (allow_with_label? && label) || (prevent_with_label? && !label))`.

Actual code at [1](#0-0) :
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Because `&&` has higher precedence than `||` in Ruby, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && label) || (prevent_with_label? && !label)`.

`review_stacks_enabled` is scoped only to the `allow_all?` term. If an operator sets `provisioning_behavior: allow_with_label` for any reason (even unrelated to review stacks) while leaving `review_stacks_enabled: false`, any pull request whose labels include `repository.provisioning_label_name` makes `provision?` return `true` regardless of `review_stacks_enabled`.

Path traced: GitHub sends a genuine, correctly-signed `pull_request` webhook (`action: "opened"`) for a repo already registered in Shipit as `Shipit::Repository` [2](#0-1) . `OpenedHandler#process` calls `respond_to_pull_request_opened?` → `provision?` [3](#0-2) . If true, `ReviewStackAdapter#find_or_create!` creates a `ReviewStack` (`Shipit::Stack` subtype) using attacker-controlled `branch: params.pull_request.head.ref` and queues it for provisioning [4](#0-3) , which later fetches and executes the attacker's `shipit.yml`/deploy pipeline on the attacker's branch. No signature/authorization guard (`verify_signature`, `require_permission!`, model validations) inspects the interaction between `review_stacks_enabled` and `provisioning_behavior`; those guards only authenticate that the webhook genuinely originates from GitHub for that repo, they don't fix the boolean logic bug itself.

### Impact Explanation
For any repository where the operator has configured `provisioning_behavior: allow_with_label` (or `prevent_with_label`) for purposes unrelated to review stacks, while leaving `review_stacks_enabled: false` (the documented opt-out of the feature), an attacker who can label their own PR forces creation of an unauthorized `ReviewStack`/`Stack` record and triggers provisioning that will execute the attacker's `shipit.yml` from their branch. This is unauthorized stack creation and code execution scoped to that repository — matches Critical impact ("a payload for one repository mutating another's stack" analog / unauthorized deploy path) since a resource is created and code execution happens for a repo whose operator never enabled that capability. It is repeatable per PR/label toggle and applies to every repository sharing this misconfiguration pattern, not a single one-off.

### Likelihood Explanation
Preconditions: repository must already be onboarded to Shipit (`Shipit::Repository` exists) with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` for other purposes, and `review_stacks_enabled: false`. Attacker cost is trivial — open a PR and apply/omit the configured label, both ordinary unprivileged actions on their own PR. No secrets, tokens, or privileged roles are required. Given `provisioning_behavior` and `review_stacks_enabled` are independent settings surfaced in `app/views/shipit/repositories/settings.html.erb`, it is plausible operators configure them independently, making this a realistic misconfiguration, not merely theoretical.

### Recommendation
Add explicit parentheses to bind `review_stacks_enabled` across the entire disjunction:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
Minitest plan (in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
```ruby
test "does not provision when review_stacks_enabled is false, even if label matches allow_with_label" do
  repository = shipit_repositories(:shipit)
  repository.update!(review_stacks_enabled: false,
                      provisioning_behavior: :allow_with_label,
                      provisioning_label_name: 'run-me')

  assert_equal false, repository.review_stacks_enabled # left side of binding

  payload = pull_request_payload(
    action: 'opened',
    repository: repository,
    labels: [{ name: 'run-me' }]
  )

  assert_no_difference -> { Shipit::Stack.count } do
    Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(payload).process
  end
end
```
Before the fix, `Shipit::Stack.count` increases despite `review_stacks_enabled: false`, proving `provision?` (right side) diverges from the intended `review_stacks_enabled` (left side) binding. After applying the parenthesization fix, the assertion holds and no stack is created.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-69)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```

**File:** app/models/shipit/repository.rb (L50-56)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior

    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
