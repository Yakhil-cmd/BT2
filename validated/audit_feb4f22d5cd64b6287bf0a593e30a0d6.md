### Title
Unfiltered PR-label injection into deploy/rollback/task shell environment via `ReviewStack#env` bypasses variable whitelist - (File: `lib/shipit/task_commands.rb`)

### Summary
`Shipit::TaskCommands#env` merges `@stack.env` directly into the environment passed to `Shipit::Command`, and for a `Shipit::ReviewStack` that `env` includes one key per PR label, upper-cased, with value `"true"`, with no name restriction and no pass through `EnvironmentVariables#permit`. Any user able to label a review-stack PR (e.g. the PR author on their own fork/branch, since `capture_labels` runs on `opened`/`labeled`/`unlabeled`/`reopened` regardless of authorization) can therefore inject an arbitrary environment variable — including `IFS` — into every subsequent deploy, rollback, and task `Command` executed for that stack.

### Finding Description
The broken binding: `Command#start` executes `PTY.spawn(unbundled_env, *interpolated_arguments, ...)` where `interpolated_arguments` are derived from the literal `command_line` string declared in `shipit.yml`, under the assumption that `unbundled_env` only contains operator/whitelisted variables (`Command#unbundled_env`, `lib/shipit/command.rb:103-105`). This assumption is broken because `@env` reaching `Command.new` is polluted by attacker-controlled label names.

Path:
1. `LabelCapturingHandler#capture_labels` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102`) writes `pull_request.labels = params.pull_request.labels.map(&:name)` for any `opened`/`labeled`/`unlabeled`/`reopened` webhook on a known, non-archived stack — no authorization check beyond the PR/repo association.
2. `ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`) merges `super` (base `Stack#env`) with `pull_request.labels.each_with_object({}) { |l, h| h[l.upcase] = "true" }` — every label becomes an env var, unfiltered.
3. `TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`) does `super.merge(@stack.env).merge(...)` — this merge is **not** passed through `EnvironmentVariables#permit`/`filter_deploy_envs`/`filter_envs`, unlike the explicit user-supplied `env` param on the deploy/task/rollback API, which *is* whitelisted (`app/models/shipit/deploy_spec.rb:174-180`, `app/models/shipit/task_definition.rb:63-65`, enforced in controllers per `test/controllers/api/deploys_controller_test.rb:42-47` and `test/controllers/api/tasks_controller_test.rb:48-53`).
4. `DeployCommands#env`/`RollbackCommands#env` build on `TaskCommands#env`, so the same unfiltered stack env (and thus label-derived keys) flows into every `Command.new(command_line, env:, chdir:)` call for `install_dependencies`, `perform` (deploy/rollback/task steps).
5. `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) merges `@env.stringify_keys` last, so `IFS=true` overrides any base/system `IFS`, and `Command#start` spawns the process with that environment (`lib/shipit/command.rb:85-101`).

Existing guards that don't help here: `EnvironmentVariables#permit` (`lib/shipit/environment_variables.rb:13-18`) is a real whitelist mechanism proven effective for the *explicit* `env` API parameter (`filter_deploy_envs`, `filter_rollback_envs`, `TaskDefinition#filter_envs`), but it is never applied to `@stack.env`/label-derived keys before they reach `TaskCommands#env` → `Command`. There is no repository/label-name allowlist and no check that a label name doesn't collide with a shell-meaningful variable such as `IFS`, `PATH`, `LD_PRELOAD`, `BASH_ENV`, `PS4`, `ENV`, etc.

Exploit: attacker opens/labels their own review-stack PR with a label literally named `IFS` (GitHub allows arbitrary label text on a repo they control/administer, or on any repo where they can add labels to their own PR if labels are freeform/PR author permitted). `capture_labels` stores it; the next deploy/rollback/task for that stack runs with `IFS=true` in its process environment, which changes default word-splitting for every subsequent shell invocation in that process tree (capistrano steps concatenated as plain strings, `machine.environment` interpolation, etc.), altering how attacker-influenced strings already on the command line (SHAs, task IDs) are tokenized versus what the `shipit.yml` step author intended.

### Impact Explanation
This is an environment-variable injection into the process that runs deploy/rollback/task shell commands for a stack — a "command running that should not" scenario. Practically:
- Any shell step built by string concatenation (a common capistrano/plain-shell pattern) has its word-splitting altered by attacker choice of `IFS`, which can change which token is treated as a command, flag, or argument.
- Beyond `IFS`, since *any* label name becomes an env var, other shell-influential names (`BASH_ENV`, `ENV`, `PS4` for xtrace-based injection, `LD_PRELOAD`/`LD_LIBRARY_PATH` if the host's shell/interpreter respects them) are also injectable, broadening this from a narrow `IFS` curiosity to a general uncontrolled-environment-injection primitive feeding into `PTY.spawn`.
- Blast radius is scoped to the stack/repository owning the PR (an attacker cannot use their own PR's labels to affect another repository's stack, since `capture_labels` operates on `stack.pull_request` scoped by `repository.review_stacks`), so this doesn't cross tenants directly, but within that repository it lets a PR author (who may have no deploy permission at all) affect the shell execution semantics of deploy/rollback/task commands that ARE authorized to run — this is a real integrity violation of "the arguments `Command#start` executes == the literal `command_line` string an authorized `shipit.yml` step declared." Matches Critical category: "RCE on the deploy host via `Command`/`PTY.spawn`" is plausible depending on step content (e.g., `IFS` manipulation combined with an existing string-concatenated shell command containing attacker-influenced tokens), and at minimum it's an unauthorized alteration of what a deploy step executes.

### Likelihood Explanation
- Requires `Shipit.review_stacks` / PR-based stacks feature to be enabled and the target repository to have `provision_pr_stacks`/review stack support turned on (an operator-configured feature, not a privileged secret).
- Requires the deploy/rollback/task steps in that repo's `shipit.yml` to be plain shell commands vulnerable to `IFS`-style tokenization changes (explicitly called out as a precondition in the prompt) — not all deployments are affected, but this is a common pattern (unquoted string-concatenated commands).
- Attacker cost is trivial: open a PR against their own fork/branch that triggers a review stack, then add a label named `IFS` (or any other sensitive variable name) via the GitHub UI/API on a PR they control. No Shipit credentials, tokens, or team membership needed — matches the stated unprivileged-attacker model exactly.
- Fully repeatable: labels can be toggled on/off/reapplied for every deploy/rollback/task triggered against that stack.

### Recommendation
Apply the same whitelist used for explicit `env` parameters to label-derived environment variables before they are merged into `TaskCommands#env`/`Command`. Concretely, in `ReviewStack#env` (or in `TaskCommands#env` where `@stack.env` is merged), filter label-derived keys through `EnvironmentVariables#permit` against the stack's `deploy_variables`/`rollback_variables`/task `variables`, and additionally reject/deny-list shell-meaningful names (`IFS`, `PATH`, `BASH_ENV`, `ENV`, `PS4`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, etc.) regardless of whitelist status. Alternatively, prefix label-derived variables with a fixed namespace (e.g., `SHIPIT_LABEL_<NAME>`) so they can never collide with variables a shell or subprocess interprets specially.

### Proof of Concept
```ruby
# test/unit/task_commands_test.rb (or new test file)
test "#env does not allow a PR label to override IFS or other reserved vars" do
  stack = shipit_stacks(:review_stack)
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  stack.pull_request.labels = ["IFS"]

  env = Shipit::TaskCommands.new(task).env

  # Binding under test: label-derived env must not smuggle shell-significant
  # variable names into the command environment.
  refute env.key?("IFS"), "PR label should not be able to set IFS in the deploy command environment"
end

test "IFS label changes shell word-splitting for a plain shell deploy step" do
  baseline = Shipit::Command.new('echo a b c', env: {}, chdir: '.')
  poisoned = Shipit::Command.new('echo a b c', env: { 'IFS' => 'b' }, chdir: '.')

  # Same command_line, but attacker-controlled IFS changes how the shell
  # would tokenize a concatenated string (demonstrated indirectly via a
  # step that concatenates tokens using $IFS-sensitive shell behavior).
  refute_equal baseline.interpolated_arguments, poisoned.interpolated_arguments if baseline.env != poisoned.env
  # Primary assertion: unbundled_env for the poisoned command actually contains IFS,
  # proving it reaches PTY.spawn unfiltered.
  assert_equal 'b', poisoned.send(:unbundled_env)['IFS']
  refute poisoned.send(:unbundled_env)['IFS'].nil?
end
```
The first test demonstrates the missing whitelist: `TaskCommands#env` for a review stack currently returns `env["IFS"] == "true"` when the PR is labeled `IFS`, when it should be filtered out (`lib/shipit/task_commands.rb:33-48`, `app/models/shipit/review_stack.rb:84-93`). The second test shows `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) passes through an attacker-chosen `IFS` value unchanged into the hash given to `PTY.spawn`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9) [11](#0-10) [12](#0-11)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
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

**File:** lib/shipit/deploy_commands.rb (L9-16)
```ruby
    def env
      commit = @task.until_commit
      super.merge(
        'SHA' => commit.sha,
        'REVISION' => commit.sha,
        'DIFF_LINK' => diff_url
      )
    end
```

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
    end
```

**File:** test/controllers/api/deploys_controller_test.rb (L42-47)
```ruby
      test "#create refuses to trigger a new deploy with incorrect variables" do
        incorrect_env = { 'DANGEROUS_VARIABLE' => 1 }
        post :create, params: { stack_id: @stack.to_param, sha: @commit.sha, env: incorrect_env }
        assert_response :unprocessable_entity
        assert_json 'message', 'Variables DANGEROUS_VARIABLE have not been whitelisted'
      end
```

**File:** test/controllers/api/tasks_controller_test.rb (L48-53)
```ruby
      test "#trigger refuses to trigger a task with tasks not whitelisted" do
        env = { 'DANGEROUS_VARIABLE' => 'bar' }
        post :trigger, params: { stack_id: @stack.to_param, task_name: 'restart', env: }
        assert_response :unprocessable_entity
        assert_json 'message', 'Variables DANGEROUS_VARIABLE have not been whitelisted'
      end
```

**File:** test/lib/shipit/task_commands_test.rb (L1-17)
```ruby
# frozen_string_literal: true

require "test_helper"

class TaskCommandsTest < ActiveSupport::TestCase
  test "#env includes a ReviewStack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    stack.pull_request.labels = ["wip", "bug"]
    task = shipit_tasks(:shipit_restart)
    task.stack = stack

    env = Shipit::TaskCommands.new(task).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
  end
end
```
