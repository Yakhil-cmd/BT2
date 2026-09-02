### Title
Unsanitized PR label names reach `Command#unbundled_env`, letting an unprivileged PR author inject `GEM_PATH`/`GEM_HOME` into deploy-host `bundle`/`gem` invocations - (File: app/models/shipit/review_stack.rb)

### Summary
`Shipit::ReviewStack#env` blindly upcases every pull-request label name and sets its value to `"true"`, merging the result into the environment used for all `bundle`/`gem` invocations in `deploy_steps`/`dependencies_steps`, with no name whitelist. An attacker who can label their own PR (as `LabelCapturingHandler` allows) can therefore set `GEM_PATH=true` or `GEM_HOME=true` on the deploy host, and because the same PR branch is checked out into the command's working directory, the attacker also controls the filesystem content that RubyGems will search under that (relative) path.

### Finding Description
Binding that is claimed and found broken: `keys(Command#unbundled_env) == keys(deploy_spec.machine_env ∪ VariableDefinition-permitted names)`. In reality, `Command#unbundled_env` performs no filtering at all: [1](#0-0) 

`@env` is whatever was passed into `Command.new(...)`, stored verbatim: [2](#0-1) 

The only whitelist in the codebase, `EnvironmentVariables#permit`, is driven by `VariableDefinition` and is used for user-submitted task-form variables (e.g. in `tasks_controller.rb`), not for `TaskCommands#env`/`ReviewStack#env`. It is never invoked on the path from webhook to `Command`.

Path:
1. Attacker labels their own PR `GEM_PATH` (case-insensitive, upcased later). `LabelCapturingHandler#process` → `capture_labels` persists the raw label names with no validation: [3](#0-2) 
2. `ReviewStack#env` reads `pull_request.labels`, upcases each and sets `"true"`, merging into the stack env: [4](#0-3) 
3. `TaskCommands#env` (used by `DeployCommands`/`RollbackCommands` too) merges `@stack.env` directly: [5](#0-4) 
4. `install_dependencies`/`perform` build `Command.new(command_line, env:, chdir: steps_directory)` from that env for every `dependencies_steps!`/`deploy_steps!` command: [6](#0-5) 
5. `Command#start` spawns the process with `unbundled_env`, which now contains attacker-controlled `GEM_PATH=true`/`GEM_HOME=true`: [7](#0-6) 

Existing guards do not intercept this: `EnvironmentVariables#permit` sanitizes only when explicitly called with a `variable_definitions` whitelist, which happens for user-submitted task parameters, not for label-derived stack env: [8](#0-7)  There is no equivalent check in `ReviewStack#env`, `Stack#env`, or `Command#unbundled_env`.

An existing test already demonstrates the general label-to-env pattern (with `WIP`/`BUG` instead of `GEM_PATH`/`GEM_HOME`), confirming the mechanism is real and unguarded: [9](#0-8) 

What makes this exploitable beyond a cosmetic env variable is that the working directory for these commands is the checked-out PR branch itself, which the same attacker fully controls (`stack.branch = pull_request.head.ref`, checkout is of `@task.until_commit`, i.e., the attacker's own commit) via `TaskCommands#checkout`/`#clone`. A `GEM_PATH`/`GEM_HOME` value of the literal string `"true"` resolves as a relative path from that working directory, so an attacker who also commits a directory named `true/` containing a crafted `specifications/`/`gems/` layout (matching a gem name+version the project's `Gemfile`/`deploy_steps` actually requires) can cause RubyGems to resolve that gem from the attacker-supplied path during the deploy/dependency-install phase, executing attacker code on the deploy host.

### Impact Explanation
If materialized, this results in arbitrary code execution on the Shipit deploy host during `bundle install`/`bundle exec`/`gem` invocations triggered by `dependencies_steps!`/`deploy_steps!`, i.e., Critical impact per the rubric ("RCE on the deploy host via `Command`/`PTY.spawn`"). It is repeatable by any user who can open and label a pull request against a repository configured with a Shipit `ReviewStack`, and is scoped to that repository's review stack/deploy host process, not cross-tenant by itself (each repository's review stack runs its own commands, but on the shared Shipit host).

### Likelihood Explanation
Preconditions: the target repository must use `Shipit::ReviewStack` (PR-driven stacks) and its `deploy_spec`'s `dependencies_steps!`/`deploy_steps!` must invoke `bundle`/`gem` (true for any Ruby project using the built-in `BundlerDiscovery`, or a custom `shipit.yml` calling `bundle`/`gem`). The attacker needs only the ability to open a PR and add a label to it — no Shipit credentials, no GitHub team membership, and no write access beyond what's needed to label their own PR (as stipulated by the audit's attacker model). The env-variable injection step (`GEM_PATH`/`GEM_HOME` = `"true"`) is trivially and deterministically reproducible; completing the RCE additionally requires crafting a matching fake gem directory in the PR branch, which is straightforward but adds a small amount of attacker effort and depends on the target project's actual gem dependency graph.

### Recommendation
Whitelist or namespace label-derived environment variables in `Shipit::ReviewStack#env` (e.g., prefix them, such as `LABEL_<NAME>`, instead of writing directly into the raw variable namespace), and explicitly reject/strip reserved/interpreter-sensitive names (`GEM_PATH`, `GEM_HOME`, `BUNDLE_*`, `RUBYOPT`, `LD_PRELOAD`, `PATH`, etc.) before merging into `TaskCommands#env`/`Command#unbundled_env`. Alternatively, route all label-derived variables through `EnvironmentVariables#permit` against an explicit, repository-configured `VariableDefinition` whitelist, the same mechanism already used for user-submitted task variables.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (add to existing ReviewStackTest)
test "#env does not leak interpreter-sensitive variable names from PR labels" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["gem_path", "gem_home"]

  env = stack.env

  # Demonstrates the broken binding: label-derived value reaches raw env
  # with no whitelist rejection, even though GEM_PATH/GEM_HOME are not in
  # deploy_spec.machine_env or any VariableDefinition.
  assert_equal "true", env["GEM_PATH"]
  assert_equal "true", env["GEM_HOME"]
end

# test/lib/shipit/task_commands_test.rb (add)
test "#env propagates GEM_PATH/GEM_HOME poisoning from PR labels into Command env" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["gem_path"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env
  assert_equal "true", env["GEM_PATH"]

  command = Shipit::Command.new("gem env", env:, chdir: ".")
  assert_equal "true", command.unbundled_env["GEM_PATH"]
end
```
Both assertions succeed with current code, with no `Shipit::EnvironmentVariables::NotPermitted` raised anywhere in the call chain, confirming the divergence.

### Citations

**File:** lib/shipit/command.rb (L31-37)
```ruby
    def initialize(*args, chdir:, default_timeout: Shipit.default_inactivity_timeout, env: {})
      @args, options = parse_arguments(args)
      @timeout = parse_timeout(options['timeout'] || options[:timeout]) || default_timeout
      @env = env.transform_values { |v| v&.to_s }
      @chdir = chdir.to_s
      @timed_out = false
    end
```

**File:** lib/shipit/command.rb (L85-93)
```ruby
    def start(&block)
      return if @started

      @control_block = block
      @out = @pid = nil
      FileUtils.mkdir_p(@chdir)
      begin
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
        child_in.close
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
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

**File:** lib/shipit/task_commands.rb (L17-27)
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
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
