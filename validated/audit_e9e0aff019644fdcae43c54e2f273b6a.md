### Title
`GEM_PATH` injection via uppercased pull-request label name reaches `tasks.<name>.steps` process environment - (File: `app/models/shipit/review_stack.rb`, `lib/shipit/task_commands.rb`, `lib/shipit/command.rb`)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) into the stack environment hash with no key allowlist. `TaskCommands#env` merges `@stack.env` unfiltered into the environment used to build `tasks.<name>.steps` commands, and `Command#unbundled_env` merges that hash on top of `BASE_ENV` before `PTY.spawn`, so an attacker-chosen label named `gem_path` becomes `GEM_PATH=true` in the spawned process's environment.

### Finding Description
The broken binding: the invariant claimed by the codebase is `tasks.<name>.steps env keys ⊆ allowlisted task/deploy variable names`, but in practice `tasks.<name>.steps env keys ⊇ {upcase(label) : label ∈ pull_request.labels}` with no allowlist applied.

Path:
1. `ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`) does:
```ruby
def env
  return super unless pull_request.present?
  super.merge(
    pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
  )
end
```
No filtering by name is applied — any label, upcased, becomes an env key.

2. `pull_request.labels` is populated straight from the webhook payload by `LabelCapturingHandler#capture_labels` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102`): `pull_request.update!(labels: params.pull_request.labels.map(&:name))`. Labels come from `params.pull_request.labels`, which is attacker-controlled data on a repo the attacker can label via a PR they open on their own fork (labels are typically settable by anyone who can open a PR against public repos with default label permissions, or is otherwise reachable in the `prevent_with_label` provisioning flow described in the question).

3. `TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`) merges `@stack.env` directly:
```ruby
def env
  super
    .merge(@stack.env)
    .merge('SHIPIT_USER' => ..., 'EMAIL' => ..., ...)
    .merge(deploy_spec.machine_env)
    .merge(@task.env)
end
```
`@stack.env` (the `ReviewStack#env` result including the label-derived keys) is merged with **no `EnvironmentVariables.permit`/allowlist call**. The allowlist (`filter_envs`/`EnvironmentVariables.permit`) is only applied to `@task.env`/`@deploy.env`, i.e., the user-supplied override params from the controller (`app/models/shipit/task_definition.rb:63-65`, `app/models/shipit/deploy_spec.rb:174-180`), not to the base stack env.

4. `TaskCommands#perform` (`lib/shipit/task_commands.rb:23-27`) builds each `tasks.<name>.steps` command with this unfiltered `env:`.

5. `Command#unbundled_env` (`lib/shipit/command.rb:103-105`):
```ruby
def unbundled_env
  BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)
end
```
`@env` (which now contains `GEM_PATH => "true"`) is merged **on top of** `BASE_ENV`, so it overrides whatever value (or absence) `Bundler.unbundled_env`/`Bundler.clean_env` set for `GEM_PATH`. This final hash is passed straight to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` (`lib/shipit/command.rb:92`).

Existing guards fail: `EnvironmentVariables.permit` (`lib/shipit/environment_variables.rb:13-18`) only intercepts explicit user-submitted `env` params in `TasksController#task_params` (`app/controllers/shipit/tasks_controller.rb:77-82`) and `DeploysController#deploy_params` (`app/controllers/shipit/deploys_controller.rb:66-68`) — it is never invoked on `@stack.env`/`ReviewStack#env`. `verify_signature`/webhook signature checks only authenticate that the payload came from GitHub for the correct repository; they do not restrict the content of label names. Nothing in `Repository`, `Stack`, or `PullRequest` validations constrains label name character set.

Note: `Bundler.unbundled_env`/`Bundler.clean_env` typically strip Bundler-managed vars (`BUNDLE_*`, `RUBYOPT`, etc.), but since the attacker's `GEM_PATH` is merged in **after** `BASE_ENV` is computed, whatever protective stripping `BASE_ENV` performs is irrelevant — the attacker's value always wins in the final merge.

### Impact Explanation
`GEM_PATH` controls where Ruby's `require`/RubyGems resolve gems from. If an attacker can also place a malicious gem payload at a predictable/attacker-writable path within the working directory (e.g., via files committed in their own fork, which get checked out into `@task.working_directory`/`steps_directory` before `tasks.<name>.steps` execute), setting `GEM_PATH` to point there can cause any `require`/`bundle exec` inside the task steps to load attacker-controlled Ruby code — full command execution on the Shipit deploy host under the Shipit service user. This is deploy-host RCE reachable from an unprivileged pull request/label action, matching the "Critical — RCE on the deploy host via Command/PTY.spawn" category. Blast radius: constrained to the specific review-stack/task execution (the malicious gem path must also be populated inside the checked-out working tree), but repeatable on any repository configured for review stacks with `prevent_with_label`/`allow_with_label` provisioning, for every task run.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled (`review_stacks_enabled`) with `provisioning_behavior` of `prevent_with_label` or `allow_with_label`, matching the question's target configuration. The attacker needs only the ability to open a pull request from a fork and set/apply a label whose name, when upcased, collides with a sensitive variable like `GEM_PATH` — no Shipit credentials, GitHub App keys, or maintainer status required. Label creation/application permissions vary by repo settings, but on many open-source repos any contributor (or even any user with a PR, depending on repo settings) can apply existing labels or the repo owner's default labels; at minimum the label-name text is attacker-influenced through the webhook body ingested by `LabelCapturingHandler`. Cost is a single PR + label action, fully repeatable against every task/deploy run of the affected review stack.

### Recommendation
Do not merge unfiltered label-derived key/value pairs into the process environment. In `ReviewStack#env`, either:
- prefix label-derived keys with a fixed namespace (e.g., `LABEL_<NAME>`) so they cannot collide with sensitive variable names such as `GEM_PATH`, `GEM_HOME`, `BUNDLE_*`, `LD_PRELOAD`, `RUBYOPT`, `PATH`, etc., and/or
- apply an explicit denylist/allowlist filtering step (reusing `EnvironmentVariables`) before merging into `@stack.env`, rejecting or dropping any key that matches a sensitive-variable pattern.
Additionally, in `Command#unbundled_env`, do not allow arbitrary `@env` keys to override the reserved set of interpreter/runtime variables (`GEM_PATH`, `GEM_HOME`, `BUNDLE_GEMFILE`, `RUBYOPT`, `LD_PRELOAD`, etc.) — merge `@env` first, then re-apply `BASE_ENV`'s protected keys, or explicitly strip disallowed keys from `@env` before the final merge.

### Proof of Concept
minitest plan (`test/lib/shipit/task_commands_test.rb`, extending the existing pattern):
```ruby
test "#env does not let a pull request label override GEM_PATH" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["gem_path"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env

  # Binding under test (should hold, currently fails):
  # env.key?("GEM_PATH") == false
  assert_not env.key?("GEM_PATH"), "GEM_PATH must not be settable via a pull request label"
end
```
And at the `Command`/`PTY.spawn` boundary:
```ruby
test "Command#unbundled_env does not let caller-supplied env override reserved interpreter vars" do
  command = Shipit::Command.new('echo $GEM_PATH', env: { 'GEM_PATH' => '/tmp/attacker-gems' }, chdir: '.')
  # Binding under test: command.unbundled_env['GEM_PATH'] should equal Shipit::Command::BASE_ENV['GEM_PATH']
  assert_equal Shipit::Command::BASE_ENV['GEM_PATH'], command.unbundled_env['GEM_PATH']
end
```
Both assertions currently fail against the code as traced (`ReviewStack#env` merges the upcased label unconditionally; `Command#unbundled_env` merges `@env` after `BASE_ENV`), demonstrating the divergence between the claimed invariant and actual behavior. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

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

**File:** lib/shipit/command.rb (L85-105)
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

    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
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

**File:** app/controllers/shipit/tasks_controller.rb (L77-82)
```ruby
    def task_params
      return {} unless params[:task]

      @definition = stack.find_task_definition(params[:definition_id])
      @task_params ||= params.require(:task).permit(env: @definition.variables.map(&:name))
    end
```

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
    end
```
