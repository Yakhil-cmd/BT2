## Answer

The audit's binding does **not** hold for `LabeledHandler`/`UnlabeledHandler`, but a materially identical bug exists in `ReopenedHandler`, which reaches the exact same `ReviewStackAdapter#unarchive!` sink.

### Where the label handlers are safe

`LabeledHandler#respond_to_label_change?` and `UnlabeledHandler#respond_to_label_change?` both gate the whole label-change branch behind `repository.review_stacks_enabled` as a *top-level* `&&` term applied to the parenthesized `(archive? || unarchive?)`: [1](#0-0) [2](#0-1) 

Because `review_stacks_enabled` is ANDed against the whole disjunction here (not against just one disjunct), disabling `review_stacks_enabled` correctly blocks `handle` → `stack.unarchive!` regardless of `provisioning_behavior`. This binding holds.

### Where the equivalent gap actually lives: `ReopenedHandler`

`ReopenedHandler#unarchive?` reproduces the exact operator-precedence bug that the question attributes to `OpenedHandler#provision?`: [3](#0-2) 

Since Ruby's `&&` binds tighter than `||`, this parses as:

```
(review_stacks_enabled && provisioning_behavior_allow_all?) ||
(provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
(provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```

`review_stacks_enabled` is only ANDed into the `allow_all` disjunct. For any repository configured with `provisioning_behavior: allow_with_label` or `prevent_with_label`, `unarchive?` returns `true` **independent of `review_stacks_enabled`**. This flows straight into `stack.unarchive!`, which calls `ReviewStackAdapter#unarchive!`: [4](#0-3) 

and either creates a brand-new stack (`create!`, which itself calls `Shipit::ReviewStackProvisioningQueue.add(stack)` unconditionally, line 82) or re-queues an existing archived stack for provisioning (line 47), which ultimately drives `TaskCommands#perform` against `params.pull_request.head.ref` (the attacker's branch), per `stack_attributes`: [5](#0-4) 

### Exploit flow

1. Operator configures a repo with `provisioning_behavior = :allow_with_label` (or `prevent_with_label`) and `review_stacks_enabled = true`.
2. Attacker opens a PR from their fork, applies/controls the provisioning label on their own PR (explicitly permitted attacker capability), a review stack gets provisioned normally.
3. Operator later sets `review_stacks_enabled = false` as a kill switch (e.g., incident response, abuse).
4. Attacker closes and reopens their own PR (both legitimate self-triggered GitHub actions the attacker fully controls, generating genuine `closed`/`reopened` webhooks — no signature forgery needed).
5. `ReopenedHandler#respond_to_pull_request_reopened?` → `unarchive?` evaluates `true` because the `allow_with_label`/`prevent_with_label` disjunct is not gated by `review_stacks_enabled`.
6. `ReviewStackAdapter#unarchive!` re-enqueues provisioning (`ReviewStackProvisioningQueue.add(stack)`) and unarchives the stack, causing task execution against the attacker's branch even though the operator explicitly disabled review-stack provisioning for the repository.

None of the existing tests cover `review_stacks_enabled: false` combined with `allow_with_label`/`prevent_with_label` for `ReopenedHandler` — every test helper `configure_provisioning_behavior` in `reopened_handler_test.rb` defaults `provisioning_enabled: true` and is never overridden to `false` in the `allow_with_label`/`prevent_with_label` test cases: [6](#0-5) , confirming this path is untested and unguarded.

### Binding evaluated

- Claimed binding: `repository.review_stacks_enabled` at unarchive-time (reopened event) must equal `repository.review_stacks_enabled` at the time provisioning would otherwise be refused.
- For `LabeledHandler`/`UnlabeledHandler`: binding **holds** — `review_stacks_enabled` is correctly re-checked and enforced on every label-change event.
- For `ReopenedHandler` with `provisioning_behavior` in `{allow_with_label, prevent_with_label}`: binding **fails** — `review_stacks_enabled` is silently dropped from the check due to `&&`/`||` precedence, so a "reopened" webhook re-provisions the stack even after the operator disables review stacks.

### Recommendation

Parenthesize `ReopenedHandler#unarchive?` (mirroring the same fix needed in `OpenedHandler#provision?`) so `review_stacks_enabled` is ANDed against the entire disjunction:

```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of concept sketch

```ruby
test "does not unarchive/provision when review_stacks_enabled is disabled, even with allow_with_label" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  Shipit::ReviewStackProvisioningQueue.expects(:add).never

  Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process

  assert stack.reload.archived?, "Expected stack to remain archived when review_stacks_enabled is false"
end
```

Under current code, `ReviewStackProvisioningQueue.expects(:add).never` will fail (it is called), demonstrating the bypass. [7](#0-6) [4](#0-3)

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L79-84)
```ruby
          def respond_to_label_change?
            params.action == "unlabeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L60-75)
```ruby

          def pull_request
            params.pull_request
          end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-50)
```ruby
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

**File:** test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb (L200-207)
```ruby
          def configure_provisioning_behavior(repository:, provisioning_enabled: true, behavior: :allow_all, label: nil)
            repository.review_stacks_enabled = provisioning_enabled
            repository.provisioning_behavior = behavior
            repository.provisioning_label_name = label
            repository.save!

            repository
          end
```
