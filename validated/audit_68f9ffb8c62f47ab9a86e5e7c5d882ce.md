### Title
Unfiltered `GIT_EXEC_PATH` injection via fork PR label name reaches `rollback.override` process environment - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) into the stack's environment hash with no key allowlist, and these labels are persisted verbatim from unauthenticated webhook payloads by `LabelCapturingHandler#capture_labels`. Because `TaskCommands#env` / `RollbackCommands#env` merge `@stack.env` directly into the environment handed to `Shipit::Command`, and `Command#unbundled_env` merges `@env` last (overriding `BASE_ENV`/`PATH`), an attacker-controlled label such as `git_exec_path` reaches `PTY.spawn` as `GIT_EXEC_PATH=true`, altering git's internal subcommand resolution for any git invocation performed during the review stack's `rollback.override` step.

### Finding Description
The broken binding: the set of environment variable keys reaching `PTY.spawn` for a review stack task should equal `Shipit.env ∪ {well-known Shipit keys} ∪ deploy_spec.machine_env ∪ (task.env filtered by deploy_spec.rollback_variables)`. In practice it equals that set **union an unbounded, attacker-chosen key set** derived from PR label names.

Path:
1. Any user who can open a fork PR against a repo with `provisioning_behavior = allow_all` can add any label to their own PR (or the webhook payload for `pull_request` events includes `labels: [{name: ...}]`, captured without further validation).
2. `LabelCapturingHandler#capture_labels` writes `params.pull_request.labels.map(&:name)` straight onto `PullRequest#labels` with no allowlist: [1](#0-0) .
3. `ReviewStack#env` turns every label name into an uppercased environment key with the fixed value `"true"`, merged with no filtering: [2](#0-1) .
4. `TaskCommands#env` (and therefore `RollbackCommands#env`, which only adds `ROLLBACK=1`) merges `@stack.env` directly into the task's command environment: [3](#0-2)  and [4](#0-3) .
5. `Command#unbundled_env` merges `@env.stringify_keys` **last**, so an attacker-supplied `GIT_EXEC_PATH` key overrides anything Shipit itself set, and this exact hash is passed to `PTY.spawn`: [5](#0-4)  and [6](#0-5) .

An existing test already demonstrates the unfiltered merge works for arbitrary label-derived keys (`WIP`, `BUG`): [7](#0-6) . There is no equivalent test or guard preventing a label such as `git_exec_path` from producing `GIT_EXEC_PATH=true` in that same hash.

Why existing guards don't stop this: `EnvironmentVariables#permit`/`filter_rollback_envs` only sanitize the **user-submitted** `task.env` (e.g., what a Shipit operator enters when triggering a rollback via the API/UI), not `@stack.env`, so the label-derived keys are never passed through the whitelist defined by `deploy_spec.rollback_variables`. `Command#unbundled_env`'s own allowlist behavior for `PATH` doesn't extend to other keys — any key in `@env` silently overrides `BASE_ENV`.

Exploit: an attacker forks the target repo, opens a PR (allowed under `allow_all`), adds a label literally named `git_exec_path` (case-insensitive, GitHub allows arbitrary label text), and in the same repository content creates a subdirectory literally named `true` in the checked-out working tree containing a malicious executable named after a git internal helper (e.g., `git-remote-https`). When the review stack's `rollback.override` steps run `git` commands, `GIT_EXEC_PATH=true` causes git to resolve internal subcommands from that attacker-controlled relative directory, achieving code execution on the Shipit deploy host.

### Impact Explanation
This is Critical: arbitrary code execution on the Shipit deploy host via `Command#start`/`PTY.spawn`, triggerable by any unprivileged fork PR author against a repository configured with `provisioning_behavior=allow_all` (which is precisely the mode intended to let external contributors get review stacks). The blast radius is limited to review-stack tasks for that repository, but since the exploit executes on the shared deploy host, it can affect other stacks/credentials resident on that host (e.g., `GITHUB_TOKEN`).

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled with `provisioning_behavior = allow_all` (a supported, documented configuration for open contribution repos) and must have a `rollback.override` (or any step invoking `git` internally) in its `shipit.yml`. The attacker needs only a GitHub account, a fork, and the ability to label their own PR — all zero-privilege actions. This is fully repeatable and requires no secrets.

### Recommendation
Restrict `ReviewStack#env`'s label-derived keys with an explicit allowlist/prefix (e.g., only allow keys not colliding with reserved/system environment variable names, or namespace them, e.g. `PR_LABEL_<NAME>`), and/or have `Command#unbundled_env` refuse to let caller-supplied `@env` override a fixed set of security-sensitive keys (`GIT_EXEC_PATH`, `LD_PRELOAD`, `BUNDLE_*`, `PATH`, etc.) regardless of merge order.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (new test)
test "#env does not allow GIT_EXEC_PATH override via pull request label" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["git_exec_path"]

  # Binding under test: stack.env keys should be limited to a known safe set,
  # but currently includes attacker-controlled GIT_EXEC_PATH.
  assert_not_includes stack.env.keys, "GIT_EXEC_PATH"
end

# test/unit/rollback_commands_test.rb (new test)
test "GIT_EXEC_PATH injected via PR label reaches spawned rollback command env" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["git_exec_path"]
  rollback = # build a Rollback task on `stack`
  commands = RollbackCommands.new(rollback)

  command = commands.perform.first
  # LHS (expected/safe): command.env["GIT_EXEC_PATH"] should be nil
  # RHS (actual/observed): command.env["GIT_EXEC_PATH"] == "true"
  assert_nil command.env["GIT_EXEC_PATH"], "fork PR label should not control GIT_EXEC_PATH reaching PTY.spawn"
end
```
Both assertions currently fail against the traced code path (`review_stack.rb:84-93` → `task_commands.rb:33-48`/`rollback_commands.rb` → `command.rb:103-105`), confirming the divergence.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
    end
```

**File:** lib/shipit/task_commands.rb (L33-48)
```ruby
    def env
      super
        .merge(@stack.env)
        .merge(
          'SHIPIT_USER' => "#{@task.author.login} (#{normalized_author_name}) via Shipit",
          'EMAIL' => @task.author.email,
          'BUNDLE_PATH' => Rails.root.join('data', 'bundler').to_s,
          'SHIPIT_LINK' => @task.permalink,
          'TASK_ID' => @task.id.to_s,
          'IGNORED_SAFETIES' => @task.ignored_safeties? ? '1' : '0',
          'GIT_COMMITTER_NAME' => @task.user&.name || Shipit.committer_name,
          'GIT_COMMITTER_EMAIL' => @task.user&.email || Shipit.committer_email
        )
        .merge(deploy_spec.machine_env)
        .merge(@task.env)
    end
```

**File:** lib/shipit/rollback_commands.rb (L1-14)
```ruby
# frozen_string_literal: true

module Shipit
  class RollbackCommands < DeployCommands
    def steps
      deploy_spec.rollback_steps!
    end

    def env
      super.merge(
        'ROLLBACK' => '1'
      )
    end
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

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** test/lib/shipit/task_commands_test.rb (L6-16)
```ruby
  test "#env includes a ReviewStack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    stack.pull_request.labels = ["wip", "bug"]
    task = shipit_tasks(:shipit_restart)
    task.stack = stack

    env = Shipit::TaskCommands.new(task).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
  end
```
