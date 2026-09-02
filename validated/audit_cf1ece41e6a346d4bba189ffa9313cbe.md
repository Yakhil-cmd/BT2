### Title
`OpenedHandler#provision?` operator-precedence bug lets `provisioning_behavior='allow_with_label'` bypass `review_stacks_enabled=false` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` is written as `A && B || C || D`, where Ruby's `&&` binds tighter than `||`. As a result, `repository.review_stacks_enabled` (`A`) only gates the `allow_all` branch (`B`); the `allow_with_label` and `prevent_with_label` clauses (`C`, `D`) are evaluated completely independently of `review_stacks_enabled`. An attacker who opens a PR against a repository with `review_stacks_enabled=false` and `provisioning_behavior='allow_with_label'`, while attaching the matching label to their own PR, causes `provision?` to return `true` and a `ReviewStack` to be created and queued for provisioning — despite the operator never having enabled review stacks.

### Finding Description
Broken binding as an equality: the code intends `repository.review_stacks_enabled == true` to gate *all* provisioning decisions, but the actual enforced condition is `repository.review_stacks_enabled == true` **only for `allow_all`**, while for `allow_with_label`/`prevent_with_label` the enforced condition is effectively `true` unconditionally (subject only to label presence).

Code path: [1](#0-0) 

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Due to precedence this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`.

With `review_stacks_enabled=false`, `provisioning_behavior='allow_with_label'`, and the PR carrying the provisioning label, the expression evaluates to `false || true || false == true`. `respond_to_pull_request_opened?` therefore returns true, and `process` calls: [2](#0-1) 

which invokes `ReviewStackAdapter#find_or_create!` → `create!`, building the stack with `branch: params.pull_request.head.ref` (fully attacker-controlled) and immediately enqueuing it: [3](#0-2) [4](#0-3) 

The `ReviewStackProvisioningQueue#work` loop later picks the stack up and calls `stack.provision`, running the deploy pipeline for that branch, which ultimately shells out via `Command#start` using `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`: [5](#0-4) 

The comparable siblings — `LabeledHandler`, `UnlabeledHandler`, and `ReopenedHandler` — all correctly guard on `repository.review_stacks_enabled` as an explicit top-level `&&` term ANDed with the whole label-behavior disjunction: [6](#0-5) [7](#0-6) 

Note `ReopenedHandler#unarchive?` at line 70-74 has the *same* precedence flaw as `OpenedHandler#provision?`, though it's out of scope of this specific question. `UnlabeledHandler`/`LabeledHandler` avoid the bug because `review_stacks_enabled` is checked in `respond_to_label_change?` as a separate top-level `&&` term, not fused with the label-behavior boolean logic.

No other guard intercepts this: webhook signature verification (`GitHubApp#verify_webhook_signature`) only authenticates that GitHub sent the payload — it does not police repository-level `review_stacks_enabled`; `ExplicitParameters` schema validates payload shape only; there is no model validation preventing this specific behavior/flag combination (`review_stacks_enabled=false` + `provisioning_behavior='allow_with_label'` is a perfectly legal, and likely common, configuration for an operator who wants review stacks off by default).

Regarding the RCE sub-claim (shell-metacharacter branch names): `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, ...)` with an argument array, which execs the target binary directly without invoking `/bin/sh`, so a literal shell-metacharacter string in `head.ref` is not turned into shell code merely by being passed as one argv element — this part of the report is unsubstantiated without further evidence of a git/task command constructing a string that is later run through a shell. What is substantiated and independently sufficient for a Critical finding is the unauthorized creation and provisioning of a `ReviewStack`/deploy pipeline for a repository whose operator explicitly disabled review stacks.

### Impact Explanation
Any GitHub user able to open a pull request against a target repository, and to label their own PR (an action any PR author can normally perform on labels they're permitted to apply, or via a bot/webhook replay pattern where the attacker controls the PR content and can set labels on their own repo/PR), can force Shipit to create a `Shipit::ReviewStack` and enqueue it for provisioning and deployment on a repository configured with `review_stacks_enabled=false`. This bypasses the operator's explicit opt-out of the review-stack feature, resulting in unauthorized deploy-pipeline execution (`Command`/`PTY.spawn`) against attacker-influenced branch content (`shipit.yml`, deploy steps) for that repository. This matches the Critical category "unauthorized deploy" and, depending on what commands `shipit.yml` on the attacker's branch defines, can escalate to command execution on the deploy host with the deploy environment's credentials. It is repeatable for any repository configured with `provisioning_behavior='allow_with_label'`, regardless of `review_stacks_enabled`.

### Likelihood Explanation
Preconditions: target repository must have `provisioning_behavior='allow_with_label'` and a `provisioning_label_name` set (a supported, documented configuration state that repository operators may choose while explicitly keeping `review_stacks_enabled=false`, e.g., during partial rollout or feature evaluation). Attacker cost is low: open a PR and apply a label to it — both routine, unprivileged PR-author actions requiring no Shipit credentials. It is deterministic and fully repeatable per qualifying repository/PR.

### Recommendation
Add parentheses so `review_stacks_enabled` gates the entire disjunction:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the same fix to `ReopenedHandler#unarchive?`, which has the identical precedence bug.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does not create stacks for repos with review stacks disabled even when allow_with_label label is present" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,     # review_stacks_enabled = false
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Given the current code, this assertion fails: `Shipit::Stack.count` increases by 1, and `Shipit::ReviewStackProvisioningQueue.add` is invoked, demonstrating the binding `repository.review_stacks_enabled == false` diverges from the enforced enablement flag (`true`, via the `allow_with_label` branch) inside `provision?`.

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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L9-11)
```ruby
    def self.add(stack)
      stack.enqueue_for_provisioning
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L65-75)
```ruby
          def respond_to_pull_request_reopened?
            params.action == "reopened" &&
              unarchive?
          end

          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
