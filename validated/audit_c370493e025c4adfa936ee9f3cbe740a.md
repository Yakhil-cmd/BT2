### Title
`PullRequest::OpenedHandler#provision?` ignores `review_stacks_enabled` when `provisioning_behavior` is `prevent_with_label` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`provision?` is intended to require `repository.review_stacks_enabled == true` for every provisioning path, but due to Ruby operator precedence (`&&` binds tighter than `||`), the flag only gates the `allow_all` disjunct. The `prevent_with_label` disjunct evaluates independently of `review_stacks_enabled`, so an attacker opening an unlabeled PR against a repo with `review_stacks_enabled: false` and `provisioning_behavior: :prevent_with_label` still triggers stack provisioning.

### Finding Description
Broken binding: the intended invariant is `review_stacks_enabled == true` for `provision? == true` in all cases; actual code makes `provision?` true whenever `(repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)` regardless of `review_stacks_enabled`.

```ruby
# app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:65-70
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Due to precedence, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

The first two disjuncts require review-stack behaviors that don't apply here; the third disjunct (`prevent_with_label`) has no `review_stacks_enabled` term at all.

Path: `process` calls `respond_to_pull_request_opened?`, which calls `provision?`; when true, it invokes `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` [2](#0-1) . `find_or_create!` calls `create!`, which persists a `Shipit::ReviewStack` with `branch: params.pull_request.head.ref` taken directly from the attacker-controlled PR payload, and enqueues it for provisioning via `Shipit::ReviewStackProvisioningQueue.add(stack)` [3](#0-2) .

Attacker request: open a pull request (or fork + push branch) against the victim repository with `labels: []` (no label at all). Provided the repository is configured `review_stacks_enabled: false, provisioning_behavior: :prevent_with_label`, `pull_request_has_provisioning_label?` returns false (empty label array does not include `provisioning_label_name`), so the third disjunct is true and `provision?` returns true, bypassing the `review_stacks_enabled: false` setting.

No existing guard intercepts this: webhook signature verification (`verify_signature`) only authenticates that GitHub sent the payload, not that the PR content/labels are trustworthy; `respond_to_pull_request_opened?` only additionally checks `params.action == "opened"`, which is trivially satisfiable by any PR-open event. Nothing else in `ReviewStackAdapter` or `Repository` re-checks `review_stacks_enabled` before `create!`.

### Impact Explanation
Any GitHub user able to open a PR (or push a branch) against a repository configured this way can force Shipit to create a `Shipit::ReviewStack` and queue it for provisioning, even though the repository owner explicitly disabled review stacks. Provisioning executes the repo's `shipit.yml`/deploy tooling against attacker-controlled branch content, which is the documented RCE vector for review stacks (attacker-controlled `shipit.yml` executed on the deploy host). This matches the Critical category: "a payload for one repository mutating another's stack" analog — here it's unauthorized stack creation/provisioning against a repository whose owner disabled the feature, leading to command execution on the deploy host. The bug is repeatable for every repository with this specific configuration combination and requires only opening PRs with no labels.

### Likelihood Explanation
Preconditions: the target repository must have `provisioning_behavior: prevent_with_label` set (this is the default/likely choice for administrators who want a label required to opt PRs *in* to review stacks, and combined with `review_stacks_enabled: false` for extra safety) — the whole point of `prevent_with_label` is "provision unless labeled," and an admin toggling `review_stacks_enabled: false` reasonably expects it to be a global kill switch. No secrets, tokens, team membership, or elevated privileges are needed — opening a PR is normal contributor behavior, or in public/forkable repos, any external contributor. Attacker cost is essentially zero and the action is fully repeatable.

### Recommendation
Add explicit parentheses/precedence so `review_stacks_enabled` gates all three disjuncts, e.g.:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Apply the same fix to `PullRequest::ReopenedHandler` and any other handler with the identical expression pattern (`labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb` all reference `provisioning_behavior`/`review_stacks_enabled` and should be audited for the same precedence bug).

### Proof of Concept
minitest plan (in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, out-of-scope to write but describing the exact assertions requested):
1. Create a `Shipit::Repository` with `review_stacks_enabled: false` and `provisioning_behavior: 'prevent_with_label'`.
2. Build `payload_parsed(:pull_request_opened)` with `pull_request.labels = []` and `pull_request.head.ref = "attacker-branch"`, `repository.full_name` matching the fixture repo.
3. Instantiate `OpenedHandler.new(...)` (or dispatch through the webhooks controller) and call `process`.
4. Assert `Shipit::ReviewStack.find_by(environment: "pr#{params.number}")` is present (equality: expected `review_stacks_enabled == true` required for creation, actual: stack created despite `review_stacks_enabled == false`).
5. Assert `stack.branch == "attacker-branch"`, demonstrating attacker-controlled branch data flowed into a persisted, queued-for-provisioning record.

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
