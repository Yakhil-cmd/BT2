## #Vulnerability found for this question.

### Title
`OpenedHandler#provision?` operator-precedence bug bypasses `review_stacks_enabled` for `allow_with_label`/`prevent_with_label` repos - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`provision?` intends `review_stacks_enabled` to gate all automatic review-stack creation, but Ruby's `&&`/`||` precedence only applies `review_stacks_enabled` to the `allow_all` branch. Any PR author who can add the configured provisioning label to their own PR can trigger stack creation (and subsequent `shipit.yml` execution) even when the repository owner has explicitly disabled review stacks.

### Finding Description
The broken binding: the code implicitly assumes `repository.review_stacks_enabled == true` is required for `provision?` to return `true` for *any* pull request, but in fact `review_stacks_enabled` is only ANDed with the first disjunct. [1](#0-0) 

Because `&&` binds tighter than `||`, the expression parses as:

```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)
```

instead of the evidently intended:

```
review_stacks_enabled && (allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?))
```

So for repositories configured with `provisioning_behavior: allow_with_label` (or `prevent_with_label`), `review_stacks_enabled` is never consulted at all.

Exploit flow: An attacker opens a pull request from their own fork against a repository configured with `provisioning_behavior: allow_with_label` and `review_stacks_enabled: false` (owner believes this disables all auto-provisioning), and applies the repository's configured `provisioning_label_name` to their own PR (label add capability is granted in the attacker model). `process` calls `respond_to_pull_request_opened?` → `provision?`, which evaluates true via the `allow_with_label? && has_label?` clause regardless of `review_stacks_enabled`. `ReviewStackAdapter#find_or_create!`/`create!` then builds a `ReviewStack` with `branch: params.pull_request.head.ref` (attacker-controlled ref) and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)`. [2](#0-1) 

No other guard intercepts this: webhook signature verification only authenticates that GitHub sent the event (which it legitimately does, since the attacker owns the PR/fork), and does not enforce the `review_stacks_enabled` business rule; that rule is enforced purely inside `provision?`, which is broken.

### Impact Explanation
A repository maintainer who sets `review_stacks_enabled: false` expects **no** review stacks to ever auto-provision, disabling execution of PR-branch `shipit.yml` steps. Due to this bug, any PR author able to attach the provisioning label to their own PR can still force a `ReviewStack` to be created from their fork's branch, which is queued for provisioning and will execute `shipit.yml`-defined steps against that ref, ultimately reaching `Command`/`PTY.spawn` on the deploy host. This is a Critical impact: attacker-authored code execution on the deploy host, gated only by a broken safety switch the operator relied on to disable this functionality entirely. It is repeatable against any repository configured with `provisioning_behavior: allow_with_label` or `prevent_with_label`, regardless of the `review_stacks_enabled` flag.

### Likelihood Explanation
Preconditions: repository must have `provisioning_behavior` set to `allow_with_label` (or `prevent_with_label`) — a supported, documented configuration — and the operator must have separately set `review_stacks_enabled: false`, believing it to be an effective master kill-switch. Per the stated attacker model, the attacker needs only to open a PR and apply the configured label to it — no privileged credentials required. This is a pure logic bug with no additional preconditions beyond an existing repository configuration; it is deterministic and repeatable on every PR.

### Recommendation
Fix operator precedence to enforce `review_stacks_enabled` as a master gate:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
minitest (in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` style):
```ruby
test "does not create stacks when review_stacks_enabled is false even for allow_with_label with label present" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # review_stacks_enabled = false
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  # Binding under test: repository.review_stacks_enabled == false
  # should imply provision? == false regardless of label/behavior.
  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Before the fix, this assertion fails: `Stack.count` increases because `provision?` returns `true` via the `allow_with_label? && has_label?` disjunct, bypassing `review_stacks_enabled == false`.

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
