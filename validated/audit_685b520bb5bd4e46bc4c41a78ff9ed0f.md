### Title
`review_stacks_enabled` fails to gate `allow_with_label`/`prevent_with_label` provisioning due to operator precedence - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
The binding the settings UI and migration imply is `review_stacks_enabled == false ⇒ no ReviewStack is ever provisioned for that repository`. In `OpenedHandler#provision?` (and identically in `ReopenedHandler#unarchive?`), Ruby's `&&`/`||` precedence makes `review_stacks_enabled` gate only the `allow_all` branch, leaving the `allow_with_label` and `prevent_with_label` branches reachable regardless of `review_stacks_enabled`'s value.

### Finding Description
The claimed binding: `repository.review_stacks_enabled == false ⇒ provision? == false` for all `provisioning_behavior` values.

Actual code:
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Because `&&` binds tighter than `||` in Ruby, this evaluates as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

The `review_stacks_enabled` term is parenthesized only with the first disjunct. Once a repository has `provisioning_behavior` set to `prevent_with_label` (or `allow_with_label`), `provision?` becomes purely a function of the label state and is fully independent of `review_stacks_enabled`. Since `!pull_request_has_provisioning_label?` is `true` for any PR without the configured label, `provision?` returns `true` for `prevent_with_label` repos on every unlabeled PR, whether or not `review_stacks_enabled` was ever turned off.

The identical pattern exists in `ReopenedHandler#unarchive?`:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [2](#0-1) 

By contrast, `LabeledHandler`/`UnlabeledHandler` correctly gate on `review_stacks_enabled` as a top-level `&&` condition before evaluating `archive?`/`unarchive?`:
```ruby
def respond_to_label_change?
  params.action == "labeled" &&
    pull_request_state == "open" &&
    repository.review_stacks_enabled &&
    (archive? || unarchive?)
end
``` [3](#0-2)  — so those two handlers are unaffected.

Attacker's exact request: an attacker (owner of the target repo, or anyone who can trigger a `pull_request` webhook for a repository already known to Shipit) opens a pull request with no labels (`POST /webhooks` delivering a `pull_request` `opened` event). No signature bypass is needed — the attacker only needs to control PR label state on a repository whose `provisioning_behavior` is `prevent_with_label`, a legitimate configuration a repo maintainer may set while leaving `review_stacks_enabled` off (e.g., toggled off temporarily, or never turned on after selecting the behavior in the settings form) — a state directly reachable from the `repositories/settings` UI.

Existing guards do not stop this: `respond_to_pull_request_opened?` only checks `params.action == "opened" && provision?` [4](#0-3) , and `provision?` itself is the broken predicate. `ExplicitParameters`/webhook signature verification validate payload shape and authenticity of the GitHub delivery, but do not enforce the `review_stacks_enabled` business gate — that enforcement is entirely inside `provision?`.

### Impact Explanation
When triggered, `Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter#find_or_create!` is invoked, creating (and later provisioning) a `ReviewStack`/`Stack` for the attacker-controlled branch/PR against a repository that has explicitly disabled review-stack auto-provisioning (`review_stacks_enabled: false`). Provisioned stacks run deploy/provisioning tasks via `Command`/`PTY.spawn` on the deploy host. This is unauthorized ReviewStack creation and command execution against a repository whose operator believed the master toggle was off, matching the "unauthorized deploy" / write-for-a-repository-that-did-not-authorize-it category. The impact is scoped to the same repository (not cross-tenant, since the label/PR is on that repository), but is repeatable for every PR and every repository configured with `provisioning_behavior: prevent_with_label` (or `allow_with_label` with a matching label) regardless of `review_stacks_enabled`.

### Likelihood Explanation
Preconditions: a Shipit repository must have `provisioning_behavior` set to `prevent_with_label` (or `allow_with_label`), which is a normal, documented configuration choice via the settings page [5](#0-4) ; `review_stacks_enabled` can be true, false, or unset — it has no effect for these two behaviors. Attacker cost is minimal: open/reopen a PR without (or with) the provisioning label. No secrets are required. Existing test coverage never exercises `provisioning_enabled: false` combined with `allow_with_label`/`prevent_with_label` in `opened_handler_test.rb` or `reopened_handler_test.rb`, so this regression is currently undetected. [6](#0-5) 

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates all three branches, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to `ReopenedHandler#unarchive?`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb
Shipit::Repository::PROVISIONING_BEHAVIORS.each do |behavior|
  test "does not create stacks when review_stacks_enabled is false (behavior=#{behavior})" do
    repository = shipit_repositories(:shipit)
    configure_provisioning_behavior(
      repository:,
      provisioning_enabled: false,
      behavior: behavior.to_sym,
      label: "pull-requests-label"
    )
    payload = payload_parsed(:pull_request_opened)
    payload["pull_request"]["labels"] = [] # no label present

    assert_no_difference -> { Shipit::Stack.count } do
      OpenedHandler.new(payload).process
    end
  end
end
```
Expected (per the `review_stacks_enabled == false ⇒ provision? == false` binding): `Stack.count` unchanged for all three behaviors. Actual: unchanged only for `allow_all`; for `prevent_with_label` (unlabeled PR) and `allow_with_label` (labeled PR) a `Stack` is created despite `review_stacks_enabled: false`, demonstrating the broken binding.

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

**File:** app/views/shipit/repositories/settings.html.erb (L16-35)
```erb
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
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L129-187)
```ruby
          test "creates stacks for repos that allow_with_label when label is present" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :allow_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end

          test "does not create stacks for repos that allow_with_label when label is absent" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :allow_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] = []

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end

          test "create stacks for repos what prevent_with_label when label is absent" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] = []

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end

          test "does not create stacks for repos what prevent_with_label when label is present" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end
```
