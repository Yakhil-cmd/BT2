### Title
`provision?` bypasses `review_stacks_enabled` for `allow_with_label`/`prevent_with_label` due to operator precedence - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`provision?` in `OpenedHandler` intends `repository.review_stacks_enabled == true` to gate every provisioning path, but Ruby's `&&`/`||` precedence only binds `review_stacks_enabled` to the `allow_all` branch. A repository with `review_stacks_enabled: false` and `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` will still satisfy `provision?`, causing an automatic review-stack creation on PR open even though review stacks are disabled for that repo.

### Finding Description
The binding the question asserts should hold is: `repository.review_stacks_enabled == true` for every truthy return of `provision?`. The actual code is: [1](#0-0) 
Due to `&&` binding tighter than `||`, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`.
Only the first disjunct is gated by `review_stacks_enabled`; the second and third are not. Consequently, for a `Repository` row with `review_stacks_enabled: false` and `provisioning_behavior: "prevent_with_label"`, opening a PR without the provisioning label makes `provision?` return `true` (`false || false || true`), and likewise `allow_with_label` with the label present returns `true`.

This is confirmed by the schema default `review_stacks_enabled: false` for all repositories [2](#0-1) , and by contrast with the sibling `LabeledHandler`, whose author explicitly hoisted `review_stacks_enabled` as a top-level `&&` gate separate from the label-behavior logic, showing the intended design that `opened_handler.rb` fails to replicate: [3](#0-2) 

`respond_to_pull_request_opened?` calls `provision?` directly with no additional `review_stacks_enabled` check: [4](#0-3) 

When `provision?` returns true, `process` unconditionally creates a `ReviewStack` and enqueues it for provisioning: [5](#0-4) [6](#0-5) 

**Attacker's exact action:** any GitHub user able to open (or fork+PR) a pull request against a repository configured with `provisioning_behavior: prevent_with_label` (or `allow_with_label`) and `review_stacks_enabled: false` triggers the `pull_request.opened` webhook, which is processed with no session, token, or signature bypass required beyond the normal (unauthenticated-by-design) webhook path — `verify_signature`/`drop_unhandled_event` etc. only validate that the payload came from GitHub for a *registered* repo/hook; they do not enforce `review_stacks_enabled` at all, since that enforcement is expected to live entirely inside `provision?`.

**Why existing guards don't catch it:** `verify_signature`, `ExplicitParameters` schema, and `drop_unhandled_event` validate webhook authenticity and payload shape, not authorization logic; none of them re-check `review_stacks_enabled`. The only gate for "is this repo allowed to auto-provision" is `provision?` itself, and it is broken by the precedence bug.

### Impact Explanation
For any repository whose operator has configured `provisioning_behavior` to `allow_with_label` or `prevent_with_label` while `review_stacks_enabled` is `false` (a state reachable via the `repositories#update` action, which permits both fields independently: [7](#0-6) ), any pull request opener can force creation of a `Shipit::ReviewStack` and its provisioning pipeline (branch checkout, provisioning queue, and ultimately deploy/provision commands run via `Command`/`PTY.spawn` on the deploy host) despite the repository having explicitly opted out of review stacks. This is a repeatable, per-PR trigger and constitutes an unauthorized provisioning/deploy action for a repository/tenant that disabled the feature — matching the Critical category ("unauthorized deploy… for a repository that did not authenticate/opt into it").

### Likelihood Explanation
Requires a specific but plausible repository configuration: `review_stacks_enabled: false` combined with a non-default `provisioning_behavior` (`allow_with_label` or `prevent_with_label`) — e.g., an operator previously enabled review stacks with label-gated behavior and later disabled `review_stacks_enabled` without resetting `provisioning_behavior`, or manually sets these two independent fields via the settings form. Given they are two independent boolean/enum columns updatable together via `update_params`, this is an easy misconfiguration, not a contrived edge case. Once in that state, exploitation costs the attacker nothing beyond opening a PR.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the entire disjunction:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Also audit `ReopenedHandler` for the same pattern, since it shares near-identical logic.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, add:
```ruby
Repository::PROVISIONING_BEHAVIORS.each do |behavior|
  test "does not provision when review_stacks_enabled is false (behavior=#{behavior})" do
    repository = shipit_repositories(:shipit)
    repository.update!(review_stacks_enabled: false, provisioning_behavior: behavior)

    assert_no_difference -> { Shipit::Stack.count } do
      OpenedHandler.new(payload_parsed(:pull_request_opened)).process
    end
  end
end
```
Expected: fails for `allow_with_label` (PR payload carrying the provisioning label) and `prevent_with_label` (PR payload without the label), demonstrating `provision?` returns `true` despite `review_stacks_enabled == false`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-93)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end

          def archive?
            (repository.provisioning_behavior_allow_with_label? && !pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && pull_request_has_provisioning_label?)
          end

          def unarchive?
            (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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

**File:** app/controllers/shipit/repositories_controller.rb (L59-65)
```ruby
    def update_params
      params.require(:repository).permit(
        :review_stacks_enabled,
        :provisioning_behavior,
        :provisioning_label_name
      )
    end
```
