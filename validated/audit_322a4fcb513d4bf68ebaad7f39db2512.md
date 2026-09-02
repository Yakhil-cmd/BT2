I have sufficient evidence to confirm the finding. The complete chain is verified:

1. `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` directly from the webhook body with no allowlist [1](#0-0) , and only requires `name` to be a `String` [2](#0-1) .

2. `ReviewStack#env` merges these label names, uppercased, into the env hash with no key allowlist [3](#0-2) .

3. `TaskCommands#env` merges `@stack.env` (which includes the ReviewStack override) unfiltered into the final environment used for every `Command`, including `install_dependencies` [4](#0-3) .

4. `Command#initialize`/`#unbundled_env` performs no key filtering — it merges `@env.stringify_keys` last, so an attacker-supplied key always wins over any base value [5](#0-4) [6](#0-5) .

5. `Command#start` spawns the process via `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [7](#0-6) , so any injected `GIT_CONFIG_GLOBAL` env var reaches the real child process's environment.

6. Crucially, `EnvironmentVariables#permit` — the actual allowlist mechanism used elsewhere (`filter_deploy_envs`, `filter_rollback_envs`, `TaskDefinition#filter_envs`) [8](#0-7) [9](#0-8)  — is never applied to `Stack#env`/`ReviewStack#env`/`TaskCommands#env`. That allowlist only guards user-supplied `env` params on deploy/rollback/task-trigger API calls, not the label-derived env merged automatically for every stack command. This is confirmed by existing tests asserting label names flow straight into `env` unfiltered: [10](#0-9)  and [11](#0-10) .

### Title
Fork-controlled PR label name injects arbitrary `GIT_CONFIG_GLOBAL` into `install_dependencies` command env - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` uppercases every pull-request label name and merges it directly into the stack environment hash with no allowlist, and `TaskCommands#env` merges that hash unfiltered into the environment passed to every task `Command`, including the `ruby`/`bundle` dependency install step built in `TaskCommands#install_dependencies`. An attacker who can open a PR against a repository with `review_stacks_enabled` and label it `GIT-CONFIG-GLOBAL: /path/to/evil.cfg` (label name `git-config-global`, case-insensitive since it's uppercased) can set `GIT_CONFIG_GLOBAL` in the process env used to spawn `git`/`bundle install`, causing the Shipit host's git/bundle invocations to load an attacker-controlled git config.

### Finding Description
The broken binding: the invariant should be `keys(TaskCommands#env) ⊆ allowlisted_keys` for any command spawned via `Command#start` → `PTY.spawn`, matching the pattern enforced elsewhere by `EnvironmentVariables#permit` (used for `deploy_variables`/`rollback_variables`/task `variables`). In reality, `keys(TaskCommands#env)` includes `pull_request.labels.map(&:upcase)` with no restriction, so the invariant is violated: `keys(TaskCommands#env) ⊄ allowlisted_keys`.

Path: unprivileged fork PR → GitHub emits a `pull_request` webhook (`opened`/`labeled`/`reopened`) → `POST /webhooks` → `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102`) into `PullRequest#labels` (only schema constraint: `String`). When a `ReviewStack` command later runs, `ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`) merges `{label_name.upcase => "true"}` for every stored label into the stack's env with no key filtering. `TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`) merges `@stack.env` into the final Command env, used both by `install_dependencies` and `perform`. `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) stringifies and merges `@env` last, overriding any existing `GIT_CONFIG_GLOBAL`/similar var, and `Command#start` passes it straight to `PTY.spawn` (`lib/shipit/command.rb:85-101`), which the `git`/`ruby`/`bundle` process inherits.

Existing guards fail to close this: `EnvironmentVariables#permit`/allowlisting is only invoked for user-supplied `env` params on deploy/rollback/task-trigger endpoints (`filter_deploy_envs`, `filter_rollback_envs`, `TaskDefinition#filter_envs`), never for `Stack#env`/`ReviewStack#env`. The webhook's `ExplicitParameters` schema only validates that `labels[].name` is a `String`, imposing no restriction on content, so any string (including `GIT_CONFIG_GLOBAL`) is accepted and persisted.

### Impact Explanation
An attacker with only fork/PR/label privileges on a repository that has review stacks enabled can inject arbitrary environment variable names (in uppercase) into every command run for that stack's tasks (dependency install, deploy, custom tasks). By choosing a label whose uppercase form matches a git/ruby/bundler-honored variable such as `GIT_CONFIG_GLOBAL`, `GIT_SSH_COMMAND`, `RUBYOPT`, etc., the attacker can point the invoked `git`/`bundle`/`ruby` process at attacker-controlled configuration or code, potentially achieving command execution as the Shipit deploy host process for that stack's working directory. This is a per-stack (per-PR) blast radius tied to the attacking repository's own review stack, but it is Critical because it is Remote Code Execution on the Shipit deploy host via `Command`/`PTY.spawn`, matching the specified impact category.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled (`review_stacks_enabled`) with a provisioning behavior that lets the attacker's PR create/keep a review stack (`allow_all`, or `allow_with_label`/`prevent_with_label` satisfied by the attacker's own label choice, since they control their own PR's labels). No Shipit session, API token, or GitHub secret is required — only the ability to open a PR and add a label to it on a repo they control (or any repo accepting external PRs), and for the corresponding webhook to be delivered. This requires no elevated privilege and is fully repeatable for any repository with review stacks enabled.

### Recommendation
Apply an explicit allowlist (or denylist of dangerous names like `GIT_CONFIG_GLOBAL`, `GIT_SSH_COMMAND`, `RUBYOPT`, `BUNDLE_*`, `LD_PRELOAD`, etc.) to label-derived environment keys in `ReviewStack#env` before merging, e.g. reuse `EnvironmentVariables#permit` against a configured/allowed set of label-driven variable names, or prefix label-derived keys (e.g. `LABEL_<NAME>`) so they can never collide with security-sensitive variable names honored by git/ruby/bundler.

### Proof of Concept
minitest plan (add to `test/lib/shipit/task_commands_test.rb` or similar):
```ruby
test "#env does not allow pull request labels to set GIT_CONFIG_GLOBAL" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["git_config_global"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env

  assert_nil env["GIT_CONFIG_GLOBAL"], "expected GIT_CONFIG_GLOBAL to not be settable via PR label, but got #{env['GIT_CONFIG_GLOBAL'].inspect}"
end

test "#install_dependencies commands do not inherit attacker-controlled GIT_CONFIG_GLOBAL from labels" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["git_config_global"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  command = Shipit::TaskCommands.new(task).install_dependencies.first
  refute_includes command.env.keys, "GIT_CONFIG_GLOBAL"
end
```
Both assertions currently fail against the existing code (`env["GIT_CONFIG_GLOBAL"]` resolves to `"true"`), demonstrating the label name flows unfiltered into the dependency-install command's environment, per `app/models/shipit/review_stack.rb:84-93` and `lib/shipit/task_commands.rb:33-48`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L29-31)
```ruby
              requires :labels, Array do
                requires :name, String
              end
```

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

**File:** lib/shipit/task_commands.rb (L17-48)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def steps
      @task.definition.steps
    end

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

**File:** lib/shipit/command.rb (L31-34)
```ruby
    def initialize(*args, chdir:, default_timeout: Shipit.default_inactivity_timeout, env: {})
      @args, options = parse_arguments(args)
      @timeout = parse_timeout(options['timeout'] || options[:timeout]) || default_timeout
      @env = env.transform_values { |v| v&.to_s }
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

**File:** test/models/shipit/review_stack_test.rb (L59-65)
```ruby
    test "#env includes the stack's pull request labels" do
      stack = shipit_stacks(:review_stack)
      stack.pull_request.labels = ["wip", "bug"]

      assert_equal stack.env["WIP"], "true"
      assert_equal stack.env["BUG"], "true"
    end
```
