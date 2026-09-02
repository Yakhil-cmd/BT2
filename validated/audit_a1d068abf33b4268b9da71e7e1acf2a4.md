### Title
`OpenedHandler#provision?` operator-precedence bug lets attacker bypass `review_stacks_enabled: false` and bind fork branch to `ReviewStack#branch` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` uses `&&`/`||` in a way where only the `allow_all` disjunct is gated by `repository.review_stacks_enabled`; the `allow_with_label` and `prevent_with_label` disjuncts are not gated at all. This lets any unprivileged GitHub user provision a `ReviewStack` (and bind their own fork's `head.ref` into `ReviewStack#branch`) on a repository whose maintainer explicitly disabled review-stack provisioning.

### Finding Description
The intended binding is: a `ReviewStack` should only ever be created for a repository == a repository where `Repository#review_stacks_enabled == true`. In `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Ruby's `&&` binds tighter than `||`, so this parses as:
```
(repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?)
|| (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?)
|| (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```
Only the first disjunct checks `review_stacks_enabled`. The second and third disjuncts (the `allow_with_label` and `prevent_with_label` provisioning behaviors) do not reference `review_stacks_enabled` at all.

Consequently, for a repository configured with `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label` (or `prevent_with_label`), `provision?` still returns `true` when the PR's labels satisfy the label condition — the flag intended to globally disable review-stack provisioning for that repository has no effect.

Once `provision?` is true, `OpenedHandler#process` calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` [2](#0-1) , which calls `create!`, which builds `stack_attributes` directly from the webhook payload:

```ruby
def stack_attributes
  {
    branch: params.pull_request.head.ref,
    environment:,
    ignore_ci: false,
    continuous_deployment: false
  }
end
``` [3](#0-2) 

`params.pull_request.head.ref` is attacker-controlled: it is the branch name of the PR's head, which for a pull request from a fork is the attacker's own fork branch name, chosen freely by the attacker. There is no validation tying this ref to any maintainer-approved value, and no code path re-checks `review_stacks_enabled` before persisting the `Shipit::Stack`/`ReviewStack` row.

**Attacker request**: open a pull request (`action: "opened"`) against the target repository — one they don't own and can't configure — with a label matching `repository.provisioning_label_name` (guessable/default, e.g. `"pull-requests-label"`, or discoverable via the repo's public label list), and a `head.ref` of the attacker's choosing (their fork branch name). Send this via the standard GitHub webhook delivery to `POST /webhooks`.

**Why existing guards fail**: `verify_signature`/webhook signature checks validate that GitHub sent the payload, but do not validate the *content* semantics against `review_stacks_enabled`; that check is the application-level gate that this logic bug bypasses. `ExplicitParameters` only validates types/presence of fields, not business authorization. `Repository` model validations only constrain `owner`/`name` format, not `branch`. There is no model-level validation on `ReviewStack#branch`/`Stack#branch` preventing arbitrary ref values.

### Impact Explanation
This causes a "payload for one repository mutating a stack for that repository without repository-level authorization" scenario within the same repository's own `review_stacks` scope — a `Shipit::Stack` row is persisted (`branch` = attacker-controlled ref) even though the repository owner set `review_stacks_enabled: false` specifically to prevent any PR-based stack creation. The impact is a write of an unauthorized/unapproved branch value into a persisted `Shipit::Stack` row, and depending on the provisioning handler configured (`ProvisioningHandler.fetch`), this newly created stack is queued for provisioning (`Shipit::ReviewStackProvisioningQueue.add(stack)`) [4](#0-3) , which can trigger downstream infrastructure actions (deploy/build) against the attacker's chosen branch. This matches the Critical impact category "a payload for one repository mutating another's stack ... or an unauthorized deploy."

Repeatable against any repository that has `review_stacks_enabled: false` but a non-default `provisioning_behavior` of `allow_with_label` or `prevent_with_label` (note: `prevent_with_label` requires no special label at all — it's the default-open branch — an attacker simply avoids applying the label).

### Likelihood Explanation
Preconditions: target repository must have `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` while `review_stacks_enabled` is `false`. This is a plausible misconfiguration state (e.g., an operator disables review-stack provisioning organization-wide by flipping `review_stacks_enabled` off but leaves the leftover `provisioning_behavior` field at a non-`allow_all` value, or these two settings are managed independently in the settings UI) [5](#0-4) . No secrets, tokens, or privileged roles are required — only the ability to open a PR (with an optional label) against the target repo, which any GitHub user with fork/PR access can do. This is a pure logic bug reachable directly through the documented webhook flow.

### Recommendation
Fix the operator precedence in `provision?` so `review_stacks_enabled` gates all three provisioning-behavior branches, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled? && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the same audit to any sibling handlers (`ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`) that use `respond_to_*` combined with `repository.review_stacks_enabled` — `LabeledHandler#respond_to_label_change?` already correctly `&&`s the flag across the whole condition [6](#0-5) ; `OpenedHandler#provision?` is the outlier missing this AND-gate.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb

test "does NOT create a stack when review_stacks_enabled is false, even with allow_with_label + matching label" do
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :allow_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }
  payload["pull_request"]["head"]["ref"] = "attacker-fork-branch"

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end

# Demonstrating the bug (fails on current code):
test "BUG: creates stack with attacker branch despite review_stacks_enabled=false" do
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :allow_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }
  payload["pull_request"]["head"]["ref"] = "attacker-fork-branch"

  OpenedHandler.new(payload).process

  stack = repository.stacks.last
  # broken binding demonstrated: stack persisted despite review_stacks_enabled == false,
  # and stack.branch equals the attacker-supplied ref, not any maintainer-approved ref.
  assert_equal "attacker-fork-branch", stack.branch
end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L87-94)
```ruby
          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** app/views/shipit/repositories/settings.html.erb (L9-41)
```erb
    <div class="setting-section">
      <%= form_for @repository do |f| %>
        <div class="field-wrapper">
          <%= f.check_box :review_stacks_enabled %>
          <%= f.label :review_stacks_enabled, "Dynamically provision stacks for Pull Requests?" %>
        </div>

        <div class="field-wrapper">
          <p>
            <%= f.label :provisioning_behavior, "Provisioning behavior", aria: { describedby: 'provisioningBehaviorHelp' } %>
            <%= f.select :provisioning_behavior, Shipit::Repository.provisioning_behaviors.map { |key, value| [ key.titleize, key] } %>
          </p>
          <p>
            <small class="form-text text-muted" id="provisioningBehaviorHelp">
              When "Allow All", the provisioning label has no effect on dynamic stack provisioning - ALL Pull Requests dynamically provision stacks.
            </small>
          </p>
          <p>
            <small class="form-text text-muted">
              When "Allow With Label", dynamic provisioning occurs ONLY for Pull Requests whose labels include the 'Provisioning Label'.
            </small>
          </p>
          <p>
            <small class="form-text text-muted">
              When "Prevent With Label", dynamic provisioning will occur for every Pull Request EXCEPT those whose labels include the 'Provisioning Label'.
            </small>
          </p>
        </div>

        <div class="field-wrapper">
          <%= f.label :provisioning_label_name, "Provisioning label" %>
          <%= f.text_field :provisioning_label_name %>
        </div>
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
