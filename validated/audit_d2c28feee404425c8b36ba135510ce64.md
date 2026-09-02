Notably, all existing tests for `allow_with_label`/`prevent_with_label` behaviors use the default `provisioning_enabled: true` (`review_stacks_enabled` defaults to `true` via `configure_provisioning_behavior`), so the test suite never exercises the `review_stacks_enabled: false` + `allow_with_label` combination that this question targets — confirming the gap is real and untested.

### Title
`provision?` operator-precedence bug lets `allow_with_label`/`prevent_with_label` repos provision review stacks even when `review_stacks_enabled` is false - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` combines `review_stacks_enabled` and the three provisioning-behavior checks with `&&`/`||` without parentheses grouping the whole expression, so due to Ruby operator precedence `review_stacks_enabled` only gates the `allow_all?` branch. For repositories configured with `provisioning_behavior: allow_with_label` (or `prevent_with_label`), `review_stacks_enabled` is never consulted, letting an outside PR author trigger `ReviewStack` creation and provisioning on a repository whose operator explicitly disabled review stacks.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == true` is the precondition that must hold for `ReviewStackAdapter#create!` to run for that repository. Tracing `provision?`: [1](#0-0) 

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` binds tighter than `||` in Ruby, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

`review_stacks_enabled` is only ANDed into the first disjunct. For a repository with `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label`, the first clause is `false`, but the second clause `(allow_with_label? && has_label?)` evaluates purely on `provisioning_behavior` and the PR's labels — `review_stacks_enabled` never re-enters the evaluation, so `provision?` returns `true`.

Exploit flow:
1. Operator (a Shipit admin) sets `Repository#review_stacks_enabled = false` and `provisioning_behavior = allow_with_label` believing review stacks are off for the repo.
2. An unprivileged external contributor opens a pull request from their own fork/branch containing an attacker-controlled `shipit.yml`, and the PR carries (or the attacker/collaborator applies) the configured `provisioning_label_name`.
3. GitHub delivers the legitimately-signed `pull_request` `opened` webhook (no forged signature needed — this is real GitHub traffic for a real PR).
4. `OpenedHandler#process` calls `respond_to_pull_request_opened?` → `provision?` → returns `true` via the `allow_with_label?` clause, bypassing the `review_stacks_enabled` gate.
5. `ReviewStackAdapter#create!` builds a `Shipit::ReviewStack` with `branch: params.pull_request.head.ref` [2](#0-1)  and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` [3](#0-2) .
6. Provisioning/deploy tasks subsequently check out that branch and run `DeploySpec::FileSystem` steps via `TaskCommands`/`Command#start` → `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [4](#0-3) , executing commands sourced from the attacker's `shipit.yml`/branch content.

Existing guards do not stop this: webhook signature verification only proves the request came from GitHub for a real PR event on the real repository — it says nothing about whether the *repository's* `review_stacks_enabled` flag should permit provisioning, which is exactly the check that is short-circuited by the precedence bug. The `ExplicitParameters` schema only validates payload shape, not the review-stack authorization decision.

### Impact Explanation
This results in arbitrary command execution on the deploy host (`Command#start` → `PTY.spawn`) driven by attacker-controlled branch content, for any repository configured with `provisioning_behavior: allow_with_label` or `prevent_with_label` regardless of the `review_stacks_enabled` flag. This is repeatable against any such repository and matches the Critical category: "RCE on the deploy host via `Command`/`PTY.spawn`... for a repository that did not authenticate it" — here the repository operator never authorized review-stack provisioning at all.

### Likelihood Explanation
Preconditions: repository must have `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (a common non-default configuration used by teams who want label-gated review stacks) with `review_stacks_enabled: false`; for `allow_with_label` the PR additionally needs the configured label applied (which may require label-write permission depending on GitHub repo settings, or could already be present as a default label pull requests inherit); for `prevent_with_label`, the PR merely needs to omit the label, which is the default state for any new PR. This makes the `prevent_with_label` variant trivially exploitable by any external contributor with zero extra steps beyond opening a PR. Attacker cost is minimal (open a PR), and the bug is deterministic/repeatable on every "opened" event.

### Recommendation
Fix the boolean grouping so `review_stacks_enabled` gates the entire decision:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Apply the same fix pattern to any sibling handler with the same construction (e.g., `reopened_handler.rb`, which also references the same three `provisioning_behavior_*?` predicates) since the same precedence bug likely applies there too.

### Proof of Concept
Add a minitest to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does not create stacks for allow_with_label repos when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  # Binding under test: repository.review_stacks_enabled == false must prevent
  # ReviewStackAdapter#create! from running, regardless of provisioning_behavior.
  assert_equal false, repository.reload.review_stacks_enabled

  assert_no_difference -> { Shipit::ReviewStack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Currently this assertion fails (a `ReviewStack` row is created) because `provision?` returns `true` via the `allow_with_label?` clause without re-checking `review_stacks_enabled`.

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

**File:** lib/shipit/command.rb (L85-101)
```ruby
    def start(&block)
      return if @started

      @control_block = block
      @out = @pid = nil
      FileUtils.mkdir_p(@chdir)
      begin
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
        child_in.close
      rescue Errno::ENOENT
        raise NotFound, "#{Shellwords.split(interpolated_arguments.first).first}: command not found"
      rescue Errno::EACCES
        raise Denied, "#{Shellwords.split(interpolated_arguments.first).first}: Permission denied"
      end
      @started = true
      self
    end
```
