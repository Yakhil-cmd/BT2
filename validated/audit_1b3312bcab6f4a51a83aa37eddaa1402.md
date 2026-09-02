### Title
`OpenedHandler#provision?` operator-precedence bug bypasses `review_stacks_enabled` when `provisioning_behavior_allow_with_label?` is set - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::PullRequest::OpenedHandler#provision?` (and the structurally identical `ReopenedHandler#unarchive?`) combines `repository.review_stacks_enabled` with the three `provisioning_behavior_*` predicates using `&&`/`||` without parentheses grouping `review_stacks_enabled` across all three clauses. Because `&&` binds tighter than `||` in Ruby, `review_stacks_enabled` only gates the `allow_all?` branch; it is never consulted for the `allow_with_label?` or `prevent_with_label?` branches, so an attacker can force stack creation on a repository with review stacks disabled simply by adding a self-chosen label matching `repository.provisioning_label_name` to their own PR.

### Finding Description
The intended binding (per `app/views/shipit/repositories/settings.html.erb:12-13` and `docs/review_stacks.md:11`) is: `repository.review_stacks_enabled == false` implies no Review Stack is ever created for that repository, regardless of `provisioning_behavior` or label state — `review_stacks_enabled` is documented as the master switch, and `provisioning_behavior`/`provisioning_label_name` only refine behavior once enabled.

The actual code in `provision?`: [1](#0-0) 

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Due to Ruby precedence, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

`review_stacks_enabled` is only ANDed into the first disjunct. If `repository.review_stacks_enabled == false` but `repository.provisioning_behavior_allow_with_label? == true`, and the incoming PR's labels contain the string equal to `repository.provisioning_label_name`, the second disjunct alone evaluates to `true`, making `provision?` return `true` even though the repository's dynamic-provisioning master switch is off.

`respond_to_pull_request_opened?` only checks `params.action == "opened" && provision?` — there is no independent `review_stacks_enabled` guard at that layer: [2](#0-1) 

The label is fully attacker-controlled: `pull_request_has_provisioning_label?` reads `pull_request["labels"]` from the webhook payload and checks inclusion of `repository.provisioning_label_name` (a value visible to anyone via the repository settings UI): [3](#0-2) 

Once `provision?` returns `true`, `process` unconditionally calls `ReviewStackAdapter#find_or_create!`, which creates a `Stack` record and enqueues it for provisioning: [4](#0-3) [5](#0-4) 

Provisioning subsequently invokes `stack.provisioner.up` via the state machine transition: [6](#0-5) 

The exact same precedence bug exists in `ReopenedHandler#unarchive?`: [7](#0-6) 

By contrast, `LabeledHandler`/`UnlabeledHandler` are NOT affected because they gate `archive?`/`unarchive?` behind a *separate*, correctly-ANDed `repository.review_stacks_enabled` check in `respond_to_label_change?`: [8](#0-7) 

None of the existing guards (`ExplicitParameters` schema, `drop_unhandled_event`, signature verification) prevent this — they validate payload shape and authenticity of the webhook sender/repo, not the internal boolean logic gating provisioning. The existing test suite for `OpenedHandler` only exercises `provisioning_enabled: false` combined with `behavior: allow_all` (which correctly still blocks), and never tests `provisioning_enabled: false` combined with `behavior: allow_with_label` plus a matching label — the exact case this bug affects — so it went uncovered: [9](#0-8) 

### Impact Explanation
An attacker who opens (or reopens) a pull request on any repository configured with `provisioning_behavior: allow_with_label` (regardless of `review_stacks_enabled`) can add the repository's configured `provisioning_label_name` to their own PR's `labels` array in the webhook payload and force Shipit to create and provision a `Stack`/`ReviewStack` for a repository whose operator explicitly disabled dynamic provisioning. This results in unauthorized record creation (`Shipit::Stack`, `Shipit::PullRequest`) and triggers the repository's configured `ProvisioningHandler#up`, which — depending on the host application's provisioning handler implementation — can execute arbitrary provisioning logic (e.g., cluster/namespace allocation) on the deploy host, matching the Critical category ("an unauthorized deploy... record written for a repository that did not authenticate it"). The attack is repeatable against every repository with `provisioning_behavior_allow_with_label?` set and `review_stacks_enabled` false, since the operator-configured `provisioning_label_name` is visible via the Shipit repository settings UI.

### Likelihood Explanation
Preconditions: `repository.provisioning_behavior == "allow_with_label"` and `repository.review_stacks_enabled == false` (the operator intends the feature disabled but still set a label config, or left a stale label config from before disabling). Cost to the attacker is trivial — open a PR on their own fork/branch and add one label whose name matches `provisioning_label_name`, which is discoverable from the Shipit UI (`app/views/shipit/repositories/settings.html.erb:38-41`). No secrets, tokens, or privileged roles are required.

### Recommendation
Fix the operator precedence in `provision?` (and the identical bug in `ReopenedHandler#unarchive?`) so that `review_stacks_enabled` gates all three provisioning-behavior branches:

```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
minitest in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` (new test):

```ruby
test "does not create a stack when review_stacks_enabled is false even if allow_with_label label is present" do
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :allow_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```

Before the fix: `Stack.count` increases (bug confirmed — `review_stacks_enabled: false` is bypassed). After applying the recommended fix: `Stack.count` does not change, matching the intended `review_stacks_enabled == false ⇒ no stack created` binding. An equivalent test should be added for `ReopenedHandler#unarchive?`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

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

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
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
