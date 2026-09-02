### Title
`review_stacks_enabled` is bypassed for `prevent_with_label`/`allow_with_label` repos due to operator precedence in `provision?`/`unarchive?` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb], [File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`OpenedHandler#provision?` and `ReopenedHandler#unarchive?` compute `repository.review_stacks_enabled && repository.provisioning_behavior_allow_all? || (...)`. Because `&&` binds tighter than `||` in Ruby, `review_stacks_enabled` only gates the `allow_all` clause, not the `allow_with_label`/`prevent_with_label` clauses. Consequently a repository configured with `provisioning_behavior: prevent_with_label` (or `allow_with_label`) but `review_stacks_enabled: false` still provisions/unarchives review stacks, invoking `ReviewStackAdapter#find_or_create!`/`unarchive!` against `Shipit::ReviewStackProvisioningQueue`.

### Finding Description
The intended binding is: `repository.review_stacks_enabled == false` ⇒ `provision? == false` for every pull-request event, i.e. dynamic stack provisioning should never occur when the feature flag is off, regardless of `provisioning_behavior`. That binding does not hold.

In [1](#0-0) , the expression parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. The last two disjuncts are entirely independent of `review_stacks_enabled`. The same pattern is repeated in [2](#0-1)  for `unarchive?`.

By contrast, `LabeledHandler#respond_to_label_change?` correctly parenthesizes the gate: `params.action == "labeled" && pull_request_state == "open" && repository.review_stacks_enabled && (archive? || unarchive?)` [3](#0-2) , confirming the `opened`/`reopened` handlers deviate from the intended design.

The repository settings UI lets an operator independently toggle `review_stacks_enabled` and set `provisioning_behavior` to `prevent_with_label` [4](#0-3) , so a repo with `review_stacks_enabled: false` and `provisioning_behavior: prevent_with_label` is a realistic configuration an operator believes fully disables the feature.

Exploit flow: attacker opens a PR against such a repo without applying the provisioning label. `OpenedHandler#process` calls `provision?`, which evaluates true via the `prevent_with_label? && !has_label?` branch, `review_stacks_enabled` being ignored; `ReviewStackAdapter#find_or_create!` creates a `ReviewStack` from `stack_attributes` bound to the PR's `branch: params.pull_request.head.ref` (attacker-controlled fork branch) and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` [5](#0-4) . The queue worker later calls `stack.provisioner.provision?`/`stack.provision` [6](#0-5) , which is the actual point where the repo's `shipit.yml`/deploy spec on that branch is used to run tasks. The attacker can re-trigger this repeatedly by closing/reopening the PR (`ClosedHandler#process` → `archive!`, `ReopenedHandler#process` → `unarchive!`, which has the identical precedence bug), each time re-enqueuing provisioning after pushing a new `shipit.yml`.

No existing guard prevents this: `verify_signature`/webhook signature checks only authenticate that GitHub sent the payload, not that provisioning is authorized by `review_stacks_enabled`; `ExplicitParameters` schemas only validate payload shape; there is no additional check of `review_stacks_enabled` at the point where the queue actually provisions (`ReviewStackProvisioningQueue#provision` only checks `stack.provisioner.provision?`, a distinct concept from the repository-level flag already evaluated at handler time).

### Impact Explanation
Any GitHub user able to open/close/reopen a pull request against a repository configured this way (a very common "we're not ready for review apps yet" setting: `review_stacks_enabled: false`, `provisioning_behavior: prevent_with_label`) can force Shipit to create and provision a review stack bound to their own PR branch, even though the operator explicitly disabled dynamic provisioning. Because provisioning ultimately drives execution of whatever deploy/task specification (`shipit.yml`) is present on the attacker's branch, this can lead to execution of attacker-supplied task definitions on the deploy host — matching the "unauthorized deploy" / command-execution class of Critical impact. The blast radius is limited to the affected repository (branch-scoped `environment: "pr#{number}"`), but is repeatable indefinitely by the same PR author via close/reopen cycles, and applies to any repository using `prevent_with_label` or `allow_with_label` with `review_stacks_enabled: false`.

### Likelihood Explanation
Preconditions are simply a repository configuration where `provisioning_behavior` is `prevent_with_label` or `allow_with_label` while `review_stacks_enabled` is `false` — a configuration reachable purely through the settings form shown above, with no code guard preventing this combination. The attacker needs no privileges beyond opening a PR (and optionally toggling a label they can apply to their own PR, or closing/reopening it), which is available to any external contributor able to open pull requests against the repo (including forks, depending on GitHub label permissions). This is highly feasible and fully repeatable.

### Recommendation
Fix operator precedence in both `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` by explicitly gating the entire expression on `review_stacks_enabled`, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same parenthesization fix to `unarchive?` in `reopened_handler.rb`.

### Proof of Concept
Minitest plan (extend `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
```ruby
test "does not create stacks when review_stacks_enabled is false, even with prevent_with_label and no label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Before the fix, this assertion fails because `Shipit::Stack.count` increases by 1 — `provision?` evaluates `true` despite `review_stacks_enabled: false`, since `repository.review_stacks_enabled` only gates the `allow_all` disjunct [1](#0-0) . A parallel test against `ReopenedHandler#unarchive?` with `provisioning_enabled: false` and an archived stack demonstrates re-provisioning on close/reopen cycles.

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

**File:** app/views/shipit/repositories/settings.html.erb (L10-20)
```erb
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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L17-37)
```ruby
    def work
      queued_stacks.find_each(&method(:provision))
    end

    def queued_stacks
      @queued_stacks ||= Shipit::ReviewStack
                         .with_provision_status(:deprovisioned)
                         .where(awaiting_provision: true)
    end

    private

    def provision(stack)
      if stack.provisioner.provision?
        stack.provision
      else
        Rails.logger.info(
          "Putting review ReviewStack<#{stack.id}> back into the provisioning queue - #provision? was falsey."
        )
      end
    end
```
