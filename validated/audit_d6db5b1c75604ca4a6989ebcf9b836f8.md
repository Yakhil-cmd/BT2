Confirms no second gate on `review_stacks_enabled` inside `ReviewStackAdapter#create!` — the only check is in `OpenedHandler#provision?`, and there is no model-level constraint tying `provisioning_behavior` to `review_stacks_enabled` in `Repository` [1](#0-0) .

### Title
Operator-precedence bug lets attacker-chosen PR label bypass `review_stacks_enabled` and provision a stack - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` is written with `&&` binding tighter than `||`, so `review_stacks_enabled` only gates the `allow_all` branch and never gates the `allow_with_label`/`prevent_with_label` branches. Because `provisioning_label_name` is a plain, non-secret string, any user able to label their own pull request can satisfy `pull_request_has_provisioning_label?` and trigger stack provisioning even when `review_stacks_enabled` is `false`.

### Finding Description
The claimed binding is: `provision? == true` should require `repository.review_stacks_enabled == true` for every provisioning behavior, i.e. `review_stacks_enabled AND (allow_all? OR (allow_with_label? AND has_label?) OR (prevent_with_label? AND !has_label?))`. The actual code is:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [2](#0-1) 

Because Ruby's `&&` has higher precedence than `||`, this actually parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. The `review_stacks_enabled` term is parenthesized only with `allow_all?` and does not distribute across the other two disjuncts. `pull_request_has_provisioning_label?` just checks `pull_request_label_names.include?(repository.provisioning_label_name)` [3](#0-2) , and `provisioning_label_name` is a plain string attribute with no secrecy guarantee, visible via the repository settings UI form field [4](#0-3)  and effectively via the repo's own label vocabulary.

Attack flow: repository has `provisioning_behavior: allow_with_label`, some `provisioning_label_name`, but `review_stacks_enabled: false` (owner believes review stacks are off). Attacker opens a pull request and labels it with the exact provisioning label. GitHub delivers a genuine, correctly-signed `opened` webhook; `OpenedHandler#process` calls `provision?`, which evaluates the `allow_with_label? && has_label?` disjunct to `true` regardless of `review_stacks_enabled`, and `ReviewStackAdapter#find_or_create!`/`create!` creates a `ReviewStack` and enqueues provisioning [5](#0-4) . No secondary check on `review_stacks_enabled` exists inside the adapter, so nothing downstream stops it [6](#0-5) . This is a genuine (not forged) webhook, so `verify_webhook_signature` and `drop_unhandled_event` do not block it — the flaw is purely in the engine's own boolean logic, not in signature/auth handling.

### Impact Explanation
An attacker who can open a PR and apply a label matching the configured (non-secret) `provisioning_label_name` can force Shipit to create and enqueue provisioning of a `ReviewStack` for a repository whose operator explicitly disabled review-stack provisioning (`review_stacks_enabled: false`). This is unauthorized resource creation/provisioning triggered by an unprivileged actor's own pull request against a repository configuration the operator believed was safe, matching the "record written for a repository that did not authenticate it" / "unauthorized deploy" impact category (Critical). The same logic flaw affects `LabeledHandler`, `UnlabeledHandler`, and `ReopenedHandler`, all of which reuse `pull_request_has_provisioning_label?`, though those handlers do have `repository.review_stacks_enabled` as an explicit top-level `&&` in `respond_to_label_change?`/`respond_to_pull_request_reopened?` guarding the whole handler [7](#0-6) [8](#0-7)  — but `OpenedHandler#provision?` does not, since the `&&` there only binds to the first disjunct [2](#0-1) .

### Likelihood Explanation
Requires the operator to have set `provisioning_behavior` to `allow_with_label` or `prevent_with_label` while `review_stacks_enabled` is `false` — a plausible misconfiguration/leftover state since `Repository` has no validation coupling these two fields [1](#0-0) . The attacker only needs the ability to open a PR and apply a label to it (granted per the stated attacker capabilities) and knowledge of the label's text, which is not a secret and is discoverable via the repository's settings page or GitHub label list. No secrets, tokens, or privileged roles are required, making this a low-cost, repeatable bypass against any repository left in this state.

### Recommendation
Fix the operator precedence in `OpenedHandler#provision?` (and audit the analogous expressions in `LabeledHandler#archive?`/`#unarchive?`, `UnlabeledHandler#archive?`/`#unarchive?`, and `ReopenedHandler#unarchive?`) so that `review_stacks_enabled` is explicitly `&&`-ed across the whole disjunction, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
Minitest (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
```ruby
test "does NOT create a stack when review_stacks_enabled is false, even with allow_with_label and matching label" do
  repository = shipit_repositories(:shipit)
  repository.update!(
    review_stacks_enabled: false,
    provisioning_behavior: :allow_with_label,
    provisioning_label_name: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = [{ "name" => "pull-requests-label" }]

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Expected (per `AUTHORIZATION_TRUTH`): assertion passes, stack count unchanged. Actual (current code): `provision?` evaluates to `true` via the `allow_with_label? && has_label?` disjunct regardless of `review_stacks_enabled`, `find_or_create!` creates a `Shipit::ReviewStack`, and the `assert_no_difference` fails, demonstrating the divergence.

### Citations

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
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

**File:** app/views/shipit/repositories/settings.html.erb (L38-41)
```erb
        <div class="field-wrapper">
          <%= f.label :provisioning_label_name, "Provisioning label" %>
          <%= f.text_field :provisioning_label_name %>
        </div>
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-85)
```ruby
          def find_or_create!
            stack || create!
          end

          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end

          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
          end

          private

          attr_reader :params, :scope

          def action
            params.action
          end

          def repo_name
            params.repository["full_name"]
          end

          def pr_number
            params.number
          end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L65-75)
```ruby
          def respond_to_pull_request_reopened?
            params.action == "reopened" &&
              unarchive?
          end

          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
