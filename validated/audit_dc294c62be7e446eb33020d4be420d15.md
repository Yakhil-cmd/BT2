### Title
Operator precedence bug in `OpenedHandler#provision?` lets `provisioning_behavior_allow_with_label` create stacks even when `review_stacks_enabled` is `false` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` intends `repository.review_stacks_enabled` to gate *all* review-stack provisioning, but Ruby operator precedence (`&&` binds tighter than `||`) makes it only gate the `allow_all` branch. As a result, when `provisioning_behavior` is `allow_with_label` (or `prevent_with_label`), a stack is created purely based on whether the PR carries the configured label, regardless of the `review_stacks_enabled` flag. Because label-driven provisioning does not re-check `Shipit.github_teams` membership or any authorization on `sender`, any actor able to attach the configured label to a PR (self-authored) can trigger `ReviewStack` creation even on repos where an operator believes review-stack auto-provisioning is disabled.

### Finding Description
The intended binding is: `provision? == true` **iff** `repository.review_stacks_enabled == true` AND the configured provisioning-behavior condition holds. The actual code is:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Because `&&` has higher precedence than `||` in Ruby, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

So `review_stacks_enabled` is only ANDed into the first disjunct. If an operator sets `review_stacks_enabled = false` but leaves `provisioning_behavior` as `allow_with_label` (or `prevent_with_label`) — e.g., during a partial rollout, misconfiguration, or after temporarily disabling review stacks without also resetting `provisioning_behavior` — the second/third disjuncts still evaluate independently of `review_stacks_enabled` and can make `provision?` return `true`.

The label check itself, `pull_request_has_provisioning_label?`, is:
```ruby
def pull_request_has_provisioning_label?
  pull_request_label_names.include?(repository.provisioning_label_name)
end
``` [2](#0-1) 

This only checks the label name present in the webhook payload; it performs no authorization check on `params.sender['login']` against `Shipit.github_teams` or repository collaborators. `ReviewStackAdapter#create!` then creates the `ReviewStack`, its `PullRequest`, and enqueues provisioning using `params.sender['login']` as the acting user without any permission check: `Shipit::User.find_or_create_by_login!(params.sender["login"])` [3](#0-2)  and `create!` at [4](#0-3) .

Existing guards do not close this gap: `respond_to_pull_request_opened?` only checks `params.action == "opened"` and `provision?` [5](#0-4) ; there is no separate authorization step comparing `sender` against maintainers/teams anywhere in this handler or `ReviewStackAdapter`.

Note on the label-authorship precondition: whether an attacker can actually attach a label to their own PR depends on GitHub's permission model (attaching labels normally requires `triage`/`write` access on the target repo), which is outside this engine's code and cannot be verified from the codebase alone. The demonstrable, code-level bug that is squarely inside this file is the precedence flaw that decouples `review_stacks_enabled` from the label-based branches.

### Impact Explanation
Exploiting this causes an unauthorized `Shipit::ReviewStack` (and its `Shipit::PullRequest` record and provisioning queue entry) to be created for a repository whose operator has set `review_stacks_enabled = false`, believing that setting fully disables automatic provisioning. This is a record written for a repository based on a configuration state that should have prevented it, and it feeds `Shipit::ReviewStackProvisioningQueue`, which drives downstream provisioning commands. This matches the Critical category of "an unauthorized deploy/provisioning action" resulting from a divergence between configured intent (`review_stacks_enabled`) and actual enforcement. It is repeatable against any repository configured with `provisioning_behavior_allow_with_label` (or `prevent_with_label`) and `review_stacks_enabled: false`, for every PR labeled (or unlabeled) appropriately.

### Likelihood Explanation
Requires: `repository.provisioning_behavior` set to `allow_with_label` or `prevent_with_label`, `repository.review_stacks_enabled` set to `false`, and a PR opened with (or without) the configured label. This is a plausible operator misconfiguration state (e.g., temporarily disabling review stacks without resetting behavior), not the default state (`provisioning_behavior` defaults are operator-chosen, not verified to be off by default) [6](#0-5) . The label-authorship part of the attacker action depends on the attacker already having label-write permission on the target repo, which is a GitHub-side constraint not enforced or bypassed by this engine's code.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates every branch:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to the equivalent `unarchive?`/`archive?` methods in `reopened_handler.rb`, `labeled_handler.rb`, and `unlabeled_handler.rb` if they have the same precedence pattern.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, add:
```ruby
test "does NOT create a stack for allow_with_label when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # review_stacks_enabled = false
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Before the fix, this assertion fails: `Shipit::Stack.count` increases by 1 even though `review_stacks_enabled` is `false`, because `provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?` evaluates independently of `review_stacks_enabled` due to operator precedence in `provision?` [1](#0-0) .

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L72-74)
```ruby
          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L52-54)
```ruby
          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
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

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
```
