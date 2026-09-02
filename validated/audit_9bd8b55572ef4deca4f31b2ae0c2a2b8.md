### Title
Operator-precedence bug in `OpenedHandler#provision?` allows review-stack creation from a fork PR when `review_stacks_enabled` is `false` - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`provision?` in `OpenedHandler` is written as `A && B || C || D`, so `repository.review_stacks_enabled` only gates the `allow_all` branch (`A && B`) and not the `allow_with_label`/`prevent_with_label` branches (`C`, `D`) due to Ruby's `&&`/`||` precedence. An attacker who opens a fork PR carrying the repository's configured `provisioning_label_name` can trigger `ReviewStack` creation even when the repository operator has explicitly disabled review stacks (`review_stacks_enabled: false`).

### Finding Description
The claimed invariant is: `repository.review_stacks_enabled == false` implies `provision? == false` for all `provisioning_behavior` values. The actual code is: [1](#0-0) 

Because `&&` binds tighter than `||`, this parses as:
```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)
```
`review_stacks_enabled` is not distributed across the second and third disjuncts. So with `review_stacks_enabled: false`, `provisioning_behavior: 'allow_with_label'`, and the PR labeled with `provisioning_label_name`, `provision?` still returns `true`, breaking the equality the operator configuration implies.

Path: an unauthenticated GitHub webhook `pull_request` `opened` event reaches `OpenedHandler#process` [2](#0-1) , which checks `respond_to_pull_request_opened?` → `provision?` before calling `ReviewStackAdapter#find_or_create!`, which builds a `ReviewStack` with `branch: params.pull_request.head.ref` taken directly from the attacker-controlled PR payload [3](#0-2) .

Existing guards do not prevent this: webhook signature verification only authenticates that the payload came from GitHub for *some* repository the attacker controls (a fork owner can generate genuine `pull_request` webhooks for their own fork/PR against the upstream repo), not that the target repository allows review-stack provisioning. `ExplicitParameters` only validates payload shape, not business authorization. None of `force_github_authentication`, `User#authorized?`, `require_permission!`, or model validations touch `provision?`'s logic. The label and branch name come straight from attacker-supplied PR metadata (`pull_request.head.ref`, `pull_request.labels[].name`), which any fork owner fully controls.

### Impact Explanation
An attacker who owns a fork and can open a PR against the target repo (no special permission needed — anyone can open a PR on a public GitHub repo) can force creation of a `Shipit::ReviewStack`/`Shipit::Stack` record for a repository whose operator explicitly turned off `review_stacks_enabled`. This is an unauthorized record write for a repository configuration the attacker did not authenticate/consent to, and it feeds into the review-stack provisioning queue, which — per this engine's review-stack workflow — leads to git checkout/build/deploy actions against the attacker-chosen `branch` (`pull_request.head.ref`) on subsequent processing. This matches the Critical category "an unauthorized deploy... or a payload...mutating another's stack" since it creates a stack the operator's `review_stacks_enabled = false` setting was meant to forbid. It is repeatable per repository configured with `allow_with_label` and is deterministic (no timing/race required) as long as the attacker can add the configured label to their own PR, which they can (labels on your own PR from your own fork can be set if you have write access on the fork/PR, or in some GitHub configurations the PR author can self-label if they have triage permission — note: on many repos only maintainers can apply labels, which affects likelihood, see below).

### Likelihood Explanation
Preconditions: repository must have `provisioning_behavior: allow_with_label` (or `prevent_with_label`, which has a related but differently-signed exposure) with `review_stacks_enabled: false`, a somewhat unusual but plausible operator configuration (e.g., temporarily disabling review stacks while leaving the per-PR-label rule configured). The attacker must also get the configured label applied to their PR — on GitHub, label application generally requires triage/write permission on the base repository, so a fully external, no-permission attacker typically cannot self-apply labels on a repo they don't have write access to; this reduces likelihood somewhat but does not eliminate it (org members with triage access, or repos with permissive label policies, or bots that auto-label based on PR title/branch, could apply labels attacker-influenced). The core code defect is unconditional and 100% reproducible once the label/branch conditions are met — no secrets or elevated Shipit access are required.

### Recommendation
Fix operator precedence so `review_stacks_enabled` gates every disjunct, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
Minitest plan (in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` style, not included here since `test/**` is out of scope for changes but described for reproduction):
1. Create a `Shipit::Repository` fixture/record with `review_stacks_enabled: false`, `provisioning_behavior: 'allow_with_label'`, `provisioning_label_name: 'preview'`.
2. Build a `pull_request` `opened` webhook payload where `pull_request.labels` includes `{ name: 'preview' }` and `pull_request.head.ref` is an attacker-chosen branch name.
3. Assert `repository.review_stacks_enabled == false` (left side of the binding) and `OpenedHandler.new(payload).send(:provision?) == true` (right side) — demonstrating the two disagree.
4. Assert `Shipit::Stack.count` (or `Shipit::ReviewStack.count`) increases by 1 after calling `OpenedHandler.new(payload).process`, and that the created stack's `branch` equals the attacker-supplied `pull_request.head.ref`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-98)
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

          def environment
            "pr#{params.number}"
          end
```
