### Title
`OpenedHandler#provision?` operator precedence bypasses `review_stacks_enabled` for `allow_with_label`/`prevent_with_label` repositories - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`provision?` uses `&&`/`||` in a way that only binds `repository.review_stacks_enabled` to the `allow_all` clause; the `allow_with_label` and `prevent_with_label` clauses are evaluated independently of `review_stacks_enabled`. As a result, a repository with `review_stacks_enabled: false` still provisions a `ReviewStack` (and queues its `shipit.yml` for execution) if `provisioning_behavior` is `allow_with_label` (label present) or `prevent_with_label` (label absent).

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == true` for every ref whose `shipit.yml` is executed via review-stack provisioning. Tracing `provision?`: [1](#0-0) 

Ruby operator precedence makes `&&` bind tighter than `||`, so this is parsed as:
`(repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?) || (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) || (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)`

Only the first disjunct is gated by `review_stacks_enabled`; the second and third are not. `respond_to_pull_request_opened?` calls `provision?` directly and, if true, `process` immediately builds a `ReviewStackAdapter` and calls `find_or_create!`, which calls `create!` using `params.pull_request.head.ref` as the new `ReviewStack`'s `branch`: [2](#0-1) [3](#0-2) 

Attacker path: attacker owns/forks a repository configured (by a maintainer, prior to disabling review stacks, or via any other admin action) with `provisioning_behavior: allow_with_label` and later `review_stacks_enabled: false`. The attacker opens a PR on their own branch, adds the provisioning label (a label they control on their own PR/fork context per the attacker model), and the real GitHub webhook fires `pull_request.opened`. `OpenedHandler#provision?` returns true because `provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?` is true regardless of `review_stacks_enabled`, so a `Stack`/`ReviewStack` row is created with `branch: params.pull_request.head.ref` pointing at attacker-controlled ref, and `ReviewStackProvisioningQueue.add(stack)` queues it for provisioning, which downstream runs `shipit.yml`/`Command`/`PTY.spawn` steps against attacker content.

Existing guards do not stop this: webhook signature verification (`GitHubApp#verify_webhook_signature`) only authenticates that the payload genuinely came from GitHub for that repository — it does not re-derive or enforce `review_stacks_enabled`, and the attacker is triggering a real, signed webhook from their own legitimately owned repository/PR, so signature verification is satisfied trivially and provides no protection here. `Repository` model validations (`app/models/shipit/repository.rb`) constrain `owner`/`name` format only, not `provisioning_behavior` vs `review_stacks_enabled` consistency. Nothing in `ReviewStackAdapter` or `Stack`/`ReviewStack` re-checks `review_stacks_enabled` before `create!`.

### Impact Explanation
This lets an attacker who controls a PR on a repository configured with `provisioning_behavior: allow_with_label`/`prevent_with_label` cause the engine to create a `ReviewStack` and enqueue provisioning/build steps from `shipit.yml` on an attacker-chosen `branch` even when the repository owner has explicitly disabled review stacks (`review_stacks_enabled: false`). Downstream provisioning executes commands via `Command`/`PTY.spawn`, so this results in command execution driven by attacker-supplied ref/content on the Shipit host — a Critical-severity outcome (unauthorized deploy-like automation execution from attacker content) for that specific repository/tenant. It is repeatable on every PR-open event against any repository sharing this misconfiguration; blast radius is limited to repositories where an operator set `provisioning_behavior` to `allow_with_label`/`prevent_with_label` while `review_stacks_enabled` is false (a configuration mismatch), not an arbitrary cross-tenant compromise.

### Likelihood Explanation
Requires a specific repository configuration precondition: `review_stacks_enabled: false` combined with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (a state a maintainer could reach, e.g., by disabling review stacks without resetting provisioning_behavior back to default, or by these fields being independently toggleable). Given that precondition, attacker cost is trivial — open a PR and optionally add a label they control on their own fork — and the exploit is fully repeatable per PR event. The main uncertainty is how commonly repositories end up in that particular mismatched configuration in practice; this is a "config divergence" bug in the engine's own gating logic that a Devin agent or maintainer should still fix regardless of prevalence, since the code's intent is clearly to gate ALL provisioning on `review_stacks_enabled`.

### Recommendation
Group the `review_stacks_enabled` check with parentheses so it applies to every branch:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
minitest plan (under `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
1. Create a `Repository` with `review_stacks_enabled: false` and `provisioning_behavior: 'allow_with_label'`.
2. Build a payload/`params` for a `pull_request.opened` event whose `pull_request.labels` includes the repository's `provisioning_label_name`, and `head.ref` set to an attacker-controlled branch name.
3. Assert binding before: `repository.review_stacks_enabled == false` (explicitly assert `refute repository.review_stacks_enabled`).
4. Call `OpenedHandler.new(payload).process`.
5. Assert `Stack.count` (or `ReviewStack.count`) increased by 1, proving a stack was created despite `review_stacks_enabled == false` — demonstrating `provision?` returned `true` when the equality `repository.review_stacks_enabled == true` does not hold, confirming the broken binding.

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
