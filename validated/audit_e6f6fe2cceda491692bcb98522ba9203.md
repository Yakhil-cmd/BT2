### Title
`OpenedHandler#provision?` ignores `review_stacks_enabled` for the `allow_with_label`/`prevent_with_label` branches due to operator precedence - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` ANDs `repository.review_stacks_enabled` only with `provisioning_behavior_allow_all?`, not with the two other OR'd branches, so a repository configured with `provisioning_behavior_allow_with_label` but `review_stacks_enabled: false` will still provision a `ReviewStack` and enqueue it for provisioning if an attacker's own PR carries the configured provisioning label. This breaks the intended invariant `repository.review_stacks_enabled == false ⇒ no ReviewStack created`.

### Finding Description
The intended binding is: `repository.review_stacks_enabled == false` implies `Shipit::ReviewStack.exists?` for that repository stays `false` and no provisioning is enqueued. The actual code: [1](#0-0) 

is parsed by Ruby as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. `review_stacks_enabled` is only ANDed into the first disjunct. If a repository has `provisioning_behavior: allow_with_label` and `review_stacks_enabled: false`, the second disjunct `(allow_with_label? && has_label?)` can be `true` independent of `review_stacks_enabled`, making `provision?` return `true`.

This is directly comparable to the sibling handler `LabeledHandler`, which correctly ANDs `repository.review_stacks_enabled` across the entire `archive?/unarchive?` decision at the top level: [2](#0-1) 
confirming that `OpenedHandler#provision?` is inconsistent with the intended design and is the outlier/bug.

Exploit flow: an attacker who owns (or has push access to) a repository that a Shipit operator has connected with `provisioning_behavior: allow_with_label` and `review_stacks_enabled: false` opens a pull request and adds the exact `provisioning_label_name` label to it (both actions available to any unprivileged collaborator on their own PR/fork depending on repo settings, and GitHub emits a genuine, correctly-signed `pull_request` "opened" webhook for this real event — no signature forgery required). `OpenedHandler#process` calls `respond_to_pull_request_opened?` → `provision?`, which returns `true` per the flawed logic, and: [3](#0-2) 

then `ReviewStackAdapter#find_or_create!` → `create!` builds a `ReviewStack` with `branch: params.pull_request.head.ref` (attacker-controlled branch name) and adds it to `Shipit::ReviewStackProvisioningQueue`: [4](#0-3) 

The provisioning queue later provisions the stack, which reads the attacker's `shipit.yml` from their branch and runs its steps via the deploy pipeline (`TaskCommands#perform` → `Command#start` → `PTY.spawn`), executing attacker-controlled commands on the deploy host in the context of that repository.

Existing guards do not stop this: webhook signature verification only proves the event genuinely came from GitHub for that repository (which it does, since the attacker owns/authors the PR and label on their own repo/fork) — it does not enforce `review_stacks_enabled`. No model validation, `ExplicitParameters` schema check, or `require_permission!` call re-checks `review_stacks_enabled` anywhere in this path.

### Impact Explanation
This is Critical impact: attacker-controlled `shipit.yml`/deploy steps executed via `PTY.spawn` on the deploy host, for a repository whose operator explicitly disabled review stacks (`review_stacks_enabled: false`). The record (`Shipit::ReviewStack`) and provisioning enqueue happen for a repository/binding that should have been blocked. The blast radius is scoped to repositories where an operator set `provisioning_behavior_allow_with_label` while leaving `review_stacks_enabled: false` — but for those repositories the vulnerability is fully repeatable per pull request/branch, letting the attacker choose the branch (and thus the `shipit.yml`) executed.

### Likelihood Explanation
Preconditions: a Shipit-connected repository must be configured with `provisioning_behavior: allow_with_label` and `review_stacks_enabled: false` (an operator-set configuration combination that is not itself invalid/rejected by any validation seen). The attacker needs only PR-open and label-add permissions on that repository/fork, i.e., ordinary contributor capability, with no Shipit credentials required. Cost is a single pull request plus a label add; fully repeatable.

### Recommendation
Fix the operator precedence in `provision?` so `review_stacks_enabled` gates all branches, e.g.:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
1. Create a `Shipit::Repository` with `review_stacks_enabled: false`, `provisioning_behavior: "allow_with_label"`, `provisioning_label_name: "deploy-preview"`.
2. Build `pull_request` "opened" webhook params with `labels: [{ name: "deploy-preview" }]`, `head.ref: "attacker-branch"`.
3. Dispatch through `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(params).process` (or via the webhook endpoint with a validly-signed payload for the dummy app).
4. Assert both sides of the binding: before, `repository.review_stacks_enabled == false` and `Shipit::ReviewStack.exists?(repository_id: repository.id) == false`; after processing, assert `Shipit::ReviewStack.exists?(repository_id: repository.id) == true` and `Shipit::ReviewStack.last.awaiting_provision == true` (i.e., present in `ReviewStackProvisioningQueue.queued_stacks`) — demonstrating the divergence: `review_stacks_enabled == false` yet a `ReviewStack` was created and queued for provisioning.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
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
