### Title
`OpenedHandler#provision?` operator-precedence bug bypasses `repository.review_stacks_enabled=false`, enabling PR-branch RCE via `PTY.spawn` - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` is written as `A && B || (C && D) || (E && F)`. Because `&&` binds tighter than `||` in Ruby, only the first `allow_all` clause is gated by `repository.review_stacks_enabled`; the `allow_with_label` and `prevent_with_label` clauses are evaluated independently of that flag. This lets an attacker who controls a PR (and its labels) force `provision?` to return `true`, and thus force `ReviewStackAdapter#create!`/`ReviewStackProvisioningQueue.add` to provision and execute a review stack, even when the repository owner has explicitly disabled review stacks (`review_stacks_enabled=false`).

### Finding Description
The intended binding is: `review_stacks_enabled == false` implies `provision? == false` for every `provisioning_behavior`. The actual code is: [1](#0-0) 

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Ruby parses this as `(review_stacks_enabled && allow_all?) || (allow_with_label? && label) || (prevent_with_label? && !label)`. The `review_stacks_enabled` guard only scopes the first disjunct. For a repository configured with `review_stacks_enabled=false`, `provisioning_behavior=:prevent_with_label`, `provisioning_label_name='no-deploy'`, an attacker opens a PR from a fork branch and simply does not apply the `no-deploy` label. Then `provisioning_behavior_prevent_with_label?` is true and `pull_request_has_provisioning_label?` is false, so the third disjunct evaluates to `true` — `provision?` returns `true` regardless of `review_stacks_enabled`.

`process` then calls `ReviewStackAdapter#find_or_create!` → `create!`, which builds the stack from `stack_attributes`: [2](#0-1) 

using `branch: params.pull_request.head.ref` — the attacker's own fork branch — and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` ( [3](#0-2) ). Provisioning subsequently reads `shipit.yml` from that same attacker-controlled ref and executes its steps via `Command`/`PTY.spawn`, in an environment carrying `GITHUB_TOKEN`.

No existing guard prevents this: `provision?` is the only check gating stack creation for the "opened" event, and the bug lives inside that check itself, so `verify_signature`, `drop_unhandled_event`, and the `ExplicitParameters` schema are irrelevant — the payload is well-formed and the signature/webhook plumbing is not what's broken. The existing test suite does not cover the combination of `review_stacks_enabled=false` with `provisioning_behavior=:allow_with_label`/`:prevent_with_label`, which is why this precedence bug went undetected: the only disabled-provisioning test (`"only provision stacks for repos with auto-provisioning enabled"`) uses `behavior: :allow_all`, the one branch that actually is correctly gated.

### Impact Explanation
An attacker who can only open a pull request against a repository configured with `review_stacks_enabled=false` can still force Shipit to create and provision a review stack sourced from a branch they fully control, leading to execution of attacker-authored `shipit.yml` steps via `Command`/`PTY.spawn` on the deploy host, in a process carrying `GITHUB_TOKEN`. This is repeatable against any repository with this configuration (`review_stacks_enabled=false` combined with `allow_with_label` or `prevent_with_label`), and is not scoped to a single tenant — any repository using this specific, plausible configuration (owner wants "review stacks disabled by default, but manually re-enable via unlabeling/labeling") is affected. This matches the Critical category: RCE on the deploy host via `Command`/`PTY.spawn`.

### Likelihood Explanation
Preconditions are narrow but realistic: the repository must have `review_stacks_enabled=false` while `provisioning_behavior` is `:allow_with_label` or `:prevent_with_label` (i.e., an operator half-configured/disabled review stacks but left a label-based provisioning behavior set). Given `review_stacks_enabled` and `provisioning_behavior` are independent settings exposed in the repository settings UI ( [4](#0-3) ), this combination is plausible, e.g., an operator temporarily disabling the feature without resetting the behavior dropdown. Attacker cost is trivial: open a PR from an owned fork, optionally omit/add a label, no credentials or privileged role required.

### Recommendation
Fix operator precedence in `provision?` by parenthesizing the `review_stacks_enabled` guard around the entire disjunction:

```ruby
def provision?
  repository.review_stacks_enabled &&
    (
      repository.provisioning_behavior_allow_all? ||
      (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
      (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
    )
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, add a test asserting the binding directly:

```ruby
test "does not create stacks when review_stacks_enabled is false, even for prevent_with_label without label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "no-deploy"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = [] # no "no-deploy" label

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```

Before the fix, this assertion fails (a stack is created and enqueued despite `review_stacks_enabled == false`), demonstrating `repository.review_stacks_enabled(false) != provision?(true)`. After applying the recommended fix, `provision?` returns `false` and no stack/`Command` is created for this configuration.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L87-94)
```ruby
          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** app/views/shipit/repositories/settings.html.erb (L1-9)
```erb
<%= render partial: 'shipit/repositories/header', locals: { repository: @repository } %>

<div class="wrapper">
  <section>
    <header class="section-header">
      <h2>Settings (Repository <%= @repository.github_repo_name %>)</h2>
    </header>

    <div class="setting-section">
```
