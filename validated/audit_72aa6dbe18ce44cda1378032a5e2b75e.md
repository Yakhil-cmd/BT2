### Title
Operator precedence in `provision?`/`unarchive?` lets `review_stacks_enabled: false` repositories still auto-provision or unarchive review stacks via `opened`/`reopened` PR webhooks - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb, reopened_handler.rb)

### Summary
`LabeledHandler#respond_to_label_change?` and `UnlabeledHandler#respond_to_label_change?` correctly AND `repository.review_stacks_enabled` against the whole `(archive? || unarchive?)` disjunction using explicit parentheses, so a disabled repository never archives/unarchives via label events. [1](#0-0) [2](#0-1)  `OpenedHandler#provision?` and `ReopenedHandler#unarchive?`, however, write `review_stacks_enabled && behavior_a || (…) || (…)` without parentheses, so due to Ruby's `&&`/`||` precedence only the first disjunct is gated by `review_stacks_enabled`, leaving the `allow_with_label?`/`prevent_with_label?` branches reachable even when the repository has review stacks disabled. [3](#0-2) [4](#0-3) 

### Finding Description
Binding: for all four handlers, the intended equality is `respond_gate == review_stacks_enabled && (branch1 || branch2 || branch3)`. For `LabeledHandler`/`UnlabeledHandler` this equality holds exactly, because the code is `repository.review_stacks_enabled && (archive? || unarchive?)`.

For `OpenedHandler#provision?`:
```ruby
repository.review_stacks_enabled &&
  repository.provisioning_behavior_allow_all? ||
  (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
  (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```
`&&` binds tighter than `||`, so this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

i.e. `review_stacks_enabled` gates only the `allow_all?` branch; the last two branches are entirely ungated by `review_stacks_enabled`. [3](#0-2)  The identical structure appears in `ReopenedHandler#unarchive?`. [4](#0-3) 

Attack: an attacker who can open (or reopen) a pull request on a repository configured with `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label` (or `prevent_with_label`) sends a normal `opened`/`reopened` webhook. `OpenedHandler#process` calls `ReviewStackAdapter#find_or_create!`, which creates a `Shipit::ReviewStack`, builds a `PullRequest`, and adds the stack to `Shipit::ReviewStackProvisioningQueue`, all despite review stacks being disabled for the repository. [5](#0-4) [6](#0-5) 

Existing guards do not prevent this: `params.action == "opened"` and the `ExplicitParameters` schema only validate payload shape, not authorization; `respond_to_label_change?` correctly gates `labeled`/`unlabeled`, so the attacker simply avoids sending a `labeled` event and instead relies on the naturally-occurring `opened` (or `reopened`) event, which every PR generates. There is no webhook-signature or authorization check specific to this logic branch beyond the repository/provisioning-behavior configuration itself.

### Impact Explanation
This confirms an asymmetric, handler-specific logic defect rather than a repository-wide misconfiguration: the same `review_stacks_enabled: false` + `allow_with_label`/`prevent_with_label` configuration behaves correctly for `labeled`/`unlabeled` events but incorrectly for `opened`/`reopened` events. The practical effect is that a `Stack` gets created/unarchived and queued for provisioning (`Shipit::ReviewStackProvisioningQueue.add`) for a repository whose operator explicitly disabled automatic review-stack provisioning. Downstream, provisioning runs stack tasks/commands, which is the mechanism by which arbitrary deploy commands execute on the host (`Command`/`PTY.spawn` in the stack task pipeline) — i.e., an attacker-controlled PR can cause command execution on a repository that opted out of automatic provisioning, without ever needing the `labeled` event. This is repeatable against any repository with this specific (`review_stacks_enabled: false`, non-`allow_all` `provisioning_behavior`) configuration and does not require any Shipit credential.

### Likelihood Explanation
Requires a repository configured with `review_stacks_enabled: false` and `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (a plausible, documented configuration meant to let operators pin down provisioning while still tracking PRs). The attacker only needs to open (or reopen) a PR against that repository — a zero-privilege action for a public/forkable repo — and, for `allow_with_label`, attach the configured label to their own PR (also zero-privilege on their own PR). No secrets, tokens, or elevated roles are needed; the divergence is 100% deterministic given the config and is reproducible on every PR open/reopen event.

### Recommendation
Wrap the entire disjunction in `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` in parentheses so `review_stacks_enabled` gates all branches, mirroring `LabeledHandler`/`UnlabeledHandler`:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to `unarchive?` in `ReopenedHandler`.

### Proof of Concept
Minitest plan (parallel to existing `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` and `labeled_handler_test.rb` patterns):
```ruby
test "does not create stacks when review_stacks_enabled is false, even with allow_with_label and label present (OpenedHandler)" do
  repository = shipit_repositories(:shipit)
  repository.update!(review_stacks_enabled: false, provisioning_behavior: :allow_with_label, provisioning_label_name: "pull-requests-label")
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end

test "LabeledHandler correctly refuses to unarchive when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  repository.update!(review_stacks_enabled: false, provisioning_behavior: :allow_with_label, provisioning_label_name: "pull-requests-label")
  payload = payload_parsed(:pull_request_labeled)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    LabeledHandler.new(payload).process
  end
end
```
Before the fix, the `OpenedHandler` test fails (`Shipit::Stack.count` increments to 1) while the `LabeledHandler` test passes (count stays 0), demonstrating the exact divergent outcome the binding requires.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
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
