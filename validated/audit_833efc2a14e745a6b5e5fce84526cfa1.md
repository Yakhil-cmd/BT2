### Title
`provision?` ignores `review_stacks_enabled` for `allow_with_label`/`prevent_with_label` behaviors, allowing review-stack creation when review stacks are disabled - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`PullRequest::OpenedHandler#provision?` ANDs `repository.review_stacks_enabled` only with the `allow_all?` branch due to Ruby operator precedence, then ORs in the `allow_with_label?`/`prevent_with_label?` branches unconditionally. As a result, a repository with `review_stacks_enabled == false` but `provisioning_behavior == :allow_with_label` will still provision a `ReviewStack` for any pull request the attacker labels themselves, contradicting the operator-controlled global toggle.

### Finding Description
The broken binding: `repository.review_stacks_enabled == false` should imply `provision? == false` for every `provisioning_behavior`, since `review_stacks_enabled` is documented/used elsewhere as a master switch. Instead:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Because `&&` binds tighter than `||`, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && label) || (prevent_with_label? && !label)`. Only the first disjunct is gated by `review_stacks_enabled`; the other two are not. The exact same defect exists in `ReopenedHandler#unarchive?`. [2](#0-1) 

The sibling `LabeledHandler`/`UnlabeledHandler` implement the intended semantics correctly, gating the *entire* archive/unarchive decision behind `review_stacks_enabled`:
```ruby
def respond_to_label_change?
  params.action == "labeled" &&
    pull_request_state == "open" &&
    repository.review_stacks_enabled &&
    (archive? || unarchive?)
end
``` [3](#0-2) 

This confirms `review_stacks_enabled` is meant to be an unconditional master gate, and `OpenedHandler#provision?` (and `ReopenedHandler#unarchive?`) fail to apply it consistently.

Exploit flow: an attacker opens a PR on a repository they can label (their own PR, or any repo where they can add labels) with `provisioning_behavior: allow_with_label`, `provisioning_label_name: 'deploy-me'`, and `review_stacks_enabled: false`. They add the label to their own PR, then the `pull_request opened` webhook fires with `action: 'opened'`. `respond_to_pull_request_opened?` calls `provision?`, which evaluates true via the `allow_with_label? && label` branch regardless of `review_stacks_enabled`. `ReviewStackAdapter#find_or_create!` then creates a `Shipit::ReviewStack` scoped to `repository.review_stacks` [4](#0-3) , using `branch: params.pull_request.head.ref` — an attacker-controlled branch name — and enqueues it for provisioning via `Shipit::ReviewStackProvisioningQueue.add(stack)`.

No existing guard prevents this: `verify_signature`/webhook auth only checks the request came from GitHub for the associated repo, not that the operator enabled review stacks; `ExplicitParameters` only validates payload shape; there is no model validation preventing `ReviewStack` creation when `review_stacks_enabled` is false — that check is solely the responsibility of `provision?`, which is defective.

Note: `ReviewStackAdapter` is scoped to `repository.review_stacks` for the *same* repository resolved from `params.repository.full_name`, so this is not a cross-repository/cross-tenant write — it is confined to the attacker's own repository. The scoped-impact claim of "cross-repository/tenant policy violation" in the question is not supported by the code; the actual impact is limited to bypassing the `review_stacks_enabled` toggle within the same repository.

### Impact Explanation
An operator who has explicitly disabled review stacks (`review_stacks_enabled: false`) for a repository still gets a `ReviewStack` created and queued for provisioning whenever `provisioning_behavior` is `allow_with_label` or `prevent_with_label` and the label condition is met — entirely under control of whoever can label the PR. This causes unwanted infrastructure/CI provisioning against an attacker-named branch, contrary to the operator's explicit configuration. It is repeatable for every PR opened against that repository. This does not cross repository boundaries, does not grant credential exfiltration, and does not achieve RCE or authentication bypass — it is a policy-toggle bypass confined to the same repository/tenant, not the "cross-repository mutation" or "authentication bypass" severity categories defined in the rules.

### Likelihood Explanation
Requires the specific repository configuration combination in the prompt: `review_stacks_enabled: false` with `provisioning_behavior: allow_with_label` (or `prevent_with_label`) — a configuration an operator could plausibly set (e.g., disabling stacks globally while behavior settings remain at a prior value). Attacker cost is low: open a PR and add a label they control on their own PR. Feasible and repeatable against the same repository per PR opened, but not against arbitrary other repositories/tenants.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates all branches, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the same fix to `ReopenedHandler#unarchive?`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
1. Create a `Repository` fixture with `review_stacks_enabled: false`, `provisioning_behavior: 'allow_with_label'`, `provisioning_label_name: 'deploy-me'`.
2. Build payload params: `action: 'opened'`, `pull_request.labels: [{name: 'deploy-me'}]`, `pull_request.head.ref: 'attacker-branch'`, `number: N`.
3. Assert equality before: `repository.review_stacks_enabled == false` and expected `provision?`/created-stack-count should remain unchanged (`Shipit::ReviewStack.count` before == after) per intended semantics.
4. Run `OpenedHandler.new(payload).process`.
5. Assert `Shipit::ReviewStack.count` increased by 1 (demonstrating the actual, broken behavior), showing `review_stacks_enabled == false` did not prevent stack creation — the equality asserted in step 3 fails, confirming the bug.

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
