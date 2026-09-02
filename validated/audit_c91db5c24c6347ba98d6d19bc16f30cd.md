### Title
`provision?` never gates the `prevent_with_label` and `allow_with_label` branches on `review_stacks_enabled`, allowing an unprivileged PR to create a `ReviewStack` on repos with review stacks disabled - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
The `provision?` method in `OpenedHandler` combines `review_stacks_enabled` with only the first (`allow_all?`) disjunct due to Ruby's `&&`/`||` operator precedence, leaving the `allow_with_label?` and `prevent_with_label?` branches unguarded by `review_stacks_enabled`. Consequently, a repository configured with `review_stacks_enabled: false` and `provisioning_behavior: 'prevent_with_label'` will still provision a `ReviewStack` when an attacker opens a labelless PR against it.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == false` implies `provision? == false` for all `provisioning_behavior` values. Tracing `provision?`: [1](#0-0) 

Because `&&` binds tighter than `||` in Ruby, this parses as:
```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)
```
With `review_stacks_enabled == false` and `provisioning_behavior == 'prevent_with_label'`:
- Term 1: `false && allow_all?` → `false`
- Term 2: `allow_with_label? (false) && has_label?` → `false`
- Term 3: `prevent_with_label? (true) && !has_label? (true, no labels)` → `true`

`provision?` evaluates to `true` despite `review_stacks_enabled` being `false`. This flows through `respond_to_pull_request_opened?` (`process` → `Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!`), which creates and persists a `ReviewStack` and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)`: [2](#0-1) 

The attacker's exact action: open a pull request (from a fork or a branch they control) against a repository that Shipit tracks with `review_stacks_enabled: false` and `provisioning_behavior: 'prevent_with_label'`, and simply do not attach any label. GitHub's `pull_request` "opened" webhook is delivered with `action == "opened"` and an empty `labels` array, satisfying `pull_request_has_provisioning_label? == false`, hence `!pull_request_has_provisioning_label? == true`.

Existing guards do not stop this: signature/webhook verification (`verify_signature`/`GitHubApp#verify_webhook_signature`) only authenticates that the payload genuinely came from GitHub for that repository — it does not validate the logical `review_stacks_enabled` gate, and a legitimate PR opened by any GitHub user against the tracked repo produces a validly-signed webhook. `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape, not business logic. No model validation on `Repository` or `ReviewStack` checks `review_stacks_enabled` before creation; that check is solely the responsibility of this buggy `provision?` boolean expression.

### Impact Explanation
For any repository onboarded with review stacks disabled (`review_stacks_enabled: false`) but `provisioning_behavior` set to `prevent_with_label` (or `allow_with_label`, similarly unguarded), an unprivileged PR author can force creation of a `ReviewStack` row, a `PullRequest` record, and enqueue provisioning work (`ReviewStackProvisioningQueue.add`) that will eventually invoke `stack.provision`. This is an unauthorized record creation and provisioning trigger on a resource explicitly configured to have review stacks disabled — a Critical-severity issue per the impact rubric ("a payload for one repository mutating another's stack" analog: causing state changes the operator explicitly disabled). It is repeatable per PR (once per unique PR number/environment) and applies to every repository in this specific misconfigured-but-plausible state (`review_stacks_enabled: false` + non-`allow_all` `provisioning_behavior`), which is a realistic operator configuration (e.g., disabling stacks globally while still testing label-based policy, or a partially-rolled-back feature).

### Likelihood Explanation
Preconditions: the target repository must exist in Shipit with `review_stacks_enabled: false` and `provisioning_behavior` set to `prevent_with_label` (or `allow_with_label`, for the label-present case) — a valid, documented, and default-adjacent configuration (`provisioning_behavior` defaults to `allow_all` per the migration, but operators toggling behaviors independently of the enabled flag is a normal use case since these are exposed as separate settings in `repositories/settings.html.erb`). The attacker needs only the ability to open a PR against the repo (fork PR from any GitHub user, assuming the repo accepts external PRs) with no labels attached — zero privileges, zero secrets, fully repeatable.

### Recommendation
Fix operator precedence explicitly, e.g.:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

### Proof of Concept
Minitest under `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does not provision a review stack when review_stacks_enabled is false, even with prevent_with_label behavior and no label" do
  repository = shipit_repositories(:shipit)
  repository.update!(review_stacks_enabled: false, provisioning_behavior: 'prevent_with_label')

  assert_equal false, repository.review_stacks_enabled

  params = default_params.deep_merge(
    action: 'opened',
    number: 999,
    pull_request: { labels: [] },
    repository: { full_name: repository.full_name }
  )

  assert_no_difference -> { Shipit::ReviewStack.count } do
    Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(params).process
  end

  assert_equal false, Shipit::ReviewStack.exists?(environment: 'pr999')
end
```
This test currently fails (a `ReviewStack` is created) because `provision?`'s third clause `(prevent_with_label? && !has_label?)` returns `true` independent of `review_stacks_enabled`, proving `Repository#review_stacks_enabled == false` while `ReviewStack.exists?(environment: 'pr999') == true`, breaking the claimed invariant.

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
