### Title
`review_stacks_enabled` fails to gate `prevent_with_label`/`allow_with_label` provisioning due to operator precedence in `provision?` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` and the identical `ReopenedHandler#unarchive?` combine `review_stacks_enabled` with the three provisioning behaviors using `&&`/`||` without parentheses grouping the whole expression. Ruby's operator precedence makes `&&` bind tighter than `||`, so `review_stacks_enabled` only scopes the `allow_all?` branch; the `allow_with_label?` and `prevent_with_label?` branches are evaluated unconditionally, independent of whether review stacks are enabled at all.

### Finding Description
The claimed binding is: `review_stacks_enabled` gates all three provisioning behaviors (as the feature toggle documentation and naming imply) == `review_stacks_enabled` gates only `allow_all?` (as actually implemented). Tracing the code confirms the divergence: [1](#0-0) 

Ruby parses this as `(review_stacks_enabled && provisioning_behavior_allow_all?) || (provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) || (provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)`. With `review_stacks_enabled = false` and `provisioning_behavior = :prevent_with_label`, the first clause is `false`, but if the incoming pull request carries no label, `provisioning_behavior_prevent_with_label?` is `true` and `!pull_request_has_provisioning_label?` is `true`, so the third clause is `true` and `provision?` returns `true` — despite the repository owner having explicitly turned review stacks off.

The exact identical logic and bug exist in `ReopenedHandler#unarchive?`: [2](#0-1) 

`process` then unconditionally calls into the adapter which creates and provisions a `ReviewStack` once `provision?` is true: [3](#0-2) [4](#0-3) 

No other guard intervenes: `NullRepository` only protects untracked repos (`review_stacks_enabled` returns `false` there too, but it never even reaches `provisioning_behavior_prevent_with_label?` because those methods also return `false`), and there is no separate check anywhere else in the controller/webhook stack (`GitHubApp#verify_webhook_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) that re-validates `review_stacks_enabled` before provisioning.

Exploit flow: repository owner enables review-stack tracking in `prevent_with_label` mode but leaves `review_stacks_enabled = false` intending to disable the entire feature (a supported, documented configuration in `docs/review_stacks.md`, out of scope for citation but confirms the intended semantics). An unprivileged contributor — anyone who can open a pull request against that repository — opens a PR without applying the "provisioning" label. GitHub's real webhook fires `pull_request.opened`; the payload passes signature verification because it is a genuine GitHub webhook. `provision?` evaluates to `true` per the precedence bug, and `ReviewStackAdapter#create!` creates a `Shipit::ReviewStack`/`Shipit::Stack`, which is enqueued via `Shipit::ReviewStackProvisioningQueue.add(stack)` for provisioning — eventually reaching task/command execution (`Command#start`).

### Impact Explanation
An attacker (any user able to open a PR on a tracked repository configured with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false`) can cause Shipit to create and provision a `Stack`/`ReviewStack` for that repository even though the owner explicitly disabled review-stack provisioning. This results in a review-stack pipeline/task run being triggered against attacker-controlled branch content (the PR's `head.ref`) that the repository owner believed was disabled — a record written and a command run for a repository configuration that never authorized it. This is repeatable against any repository under this specific but legitimate/documented configuration, matching the "unauthorized deploy/task execution reaching `Command#start`" Critical impact category.

### Likelihood Explanation
Preconditions: the target repository must be tracked in Shipit with `provisioning_behavior = :prevent_with_label` and `review_stacks_enabled = false` — a configuration explicitly supported by the schema/enum and settings UI. No Shipit secrets, sessions, or privileged roles are needed; the attacker only needs the ability to open a pull request (or push a branch triggering one) without applying the configured label, which is trivial and free for any GitHub user with PR access to the repo. The bug fires on every such PR, making it fully repeatable.

### Recommendation
Explicitly parenthesize the boolean expression so `review_stacks_enabled` gates the entire OR-chain, e.g.:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Apply the same fix to `ReopenedHandler#unarchive?`.

### Proof of Concept
```ruby
test "does not create stacks when review_stacks_enabled is false, even for prevent_with_label without a label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,     # review_stacks_enabled = false
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []   # no label present

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Under the current implementation this assertion fails: `assert_difference -> { Shipit::Stack.count }` actually passes instead, proving a `Stack` is created despite `review_stacks_enabled = false`.

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
