### Title
Operator precedence flaw in `ReopenedHandler#unarchive?` lets `review_stacks_enabled: false` be bypassed for `allow_with_label`/`prevent_with_label` repos - (File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb)

### Summary
`ReviewStackAdapter#unarchive!`/`#find_or_create!` (re)provisioning is supposed to be gated entirely on `repository.review_stacks_enabled`, i.e. the binding `repository.review_stacks_enabled == true` should be required for any provisioning path. Because of Ruby `&&`/`||` precedence in `unarchive?`, that flag only actually gates the `allow_all` branch; the `allow_with_label` and `prevent_with_label` branches are unconditionally reachable regardless of `review_stacks_enabled`, letting an attacker resurrect/create a `ReviewStack` on a repository where review stacks have been disabled.

### Finding Description
The intended binding is: `repository.review_stacks_enabled == true` for every provisioning behavior branch before `stack.unarchive!`/`create!` runs. The actual code in `unarchive?` is: [1](#0-0) 

```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Ruby evaluates `&&` before `||`, so this parses as:

```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)
```

`review_stacks_enabled` is only ANDed into the first disjunct. The second and third disjuncts (`allow_with_label` and `prevent_with_label` behaviors) are entirely independent of `review_stacks_enabled`. `OpenedHandler#provision?` has the identical shape and the identical flaw, as noted by the question and confirmed by direct comparison: [2](#0-1) 

Attack flow for the scoped reopen scenario: repository has `review_stacks_enabled: false`, `provisioning_behavior: prevent_with_label`, no label configured/applied.
1. Attacker opens/has an existing PR whose review stack was previously archived (e.g. via a prior `closed` webhook handled by `ClosedHandler#process` calling `review_stack.archive!` — [3](#0-2) ).
2. Attacker (or GitHub, replaying the attacker's own repo webhook) sends a `reopened` action payload for that PR.
3. `ReopenedHandler#process` calls `respond_to_pull_request_reopened?` → `unarchive?`. Since `prevent_with_label?` is true and there is no provisioning label on the PR, `!pull_request_has_provisioning_label?` is true, so the third disjunct is true — `unarchive?` returns `true` even though `review_stacks_enabled` is `false`. [4](#0-3) 
4. `stack.unarchive!` (a `ReviewStackAdapter`) is invoked. If no `ReviewStack` exists it calls `create!`, and if one exists and is archived it calls `Shipit::ReviewStackProvisioningQueue.add(stack)` plus `stack.unarchive!`, resurrecting/creating a stack tied to the attacker's `pull_request.head.ref`/branch. [5](#0-4) [6](#0-5) 

No other guard intervenes: `params` schema validation only checks payload shape, not repository configuration; `respond_to_pull_request_reopened?` only checks `action == "reopened"` and `unarchive?`; there is no separate `review_stacks_enabled` short-circuit anywhere in the call path. The existing test suite for `ReopenedHandler` (`test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`) never exercises `review_stacks_enabled: false` combined with `allow_with_label`/`prevent_with_label` — `configure_provisioning_behavior` defaults `provisioning_enabled: true` in every test case — so this gap is untested and unnoticed.

### Impact Explanation
A repository administrator disables review stacks (`review_stacks_enabled: false`) expecting no PR-driven stack (re)provisioning. If `provisioning_behavior` is `prevent_with_label` (or `allow_with_label`), any PR without (or with, respectively) the provisioning label can still trigger creation or unarchiving of a `Shipit::ReviewStack` purely via `reopened`/`opened` webhook events that this engine itself accepts from the linked GitHub repository. This causes writes (`ReviewStack`/`Task` provisioning queue entries) that the repository owner explicitly opted out of, and repeats every time the attacker closes/reopens their own PR. This is a record-mutation bug — a stack gets provisioned/deprovisioned against the configuration's intent — scoped to the attacker's own repository/PR (no cross-tenant escalation demonstrated here), matching the "record written for a repository that did not authenticate/intend it" impact class described, though it does not by itself achieve RCE, credential exfiltration, or cross-repository mutation.

### Likelihood Explanation
Preconditions are narrow but plausible: the repository must have `review_stacks_enabled: false` AND `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (not the default `allow_all`), and a prior/absent `ReviewStack` state. Given those, the attacker needs no privileges beyond owning a PR against that repo — closing/reopening a PR (or POSTing the equivalent webhook payload, since `verify_signature`/webhook auth is out of the traced path per the question's framing) is trivially repeatable.

### Recommendation
Fix the operator precedence in both `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` by explicitly gating the entire expression on `review_stacks_enabled`:

```ruby
def unarchive?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`, add:

```ruby
test "does not unarchive or create stacks when review_stacks_enabled is false, even under prevent_with_label" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] = []

  Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process

  assert stack.reload.archived?, "Expected stack to remain archived when review_stacks_enabled is false"
end
```

Assert both sides of the binding: `repository.review_stacks_enabled` (`false`) must equal the value that actually gates provisioning (currently effectively `true` due to precedence) — the test demonstrates they diverge, since `stack.reload.archived?` will be `false` under current code (bug reproduced) instead of the expected `true`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
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
