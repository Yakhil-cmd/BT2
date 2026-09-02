### Title
Untrusted `machine.environment` from a fork's `shipit.yml` is merged unfiltered into the process env reaching `PTY.spawn`, enabling `BASH_ENV`-based RCE - (File: `lib/shipit/task_commands.rb`, `app/models/shipit/deploy_spec.rb`, `lib/shipit/command.rb`)

### Summary
`TaskCommands#env` (and the analogous `DeployCommands#env`) merges `deploy_spec.machine_env`, which is read straight from the `shipit.yml` checked out from the review stack's own branch, into the environment passed to `Command.new`. Unlike `deploy.variables` / `rollback.variables` / task `variables`, which are sanitized through `EnvironmentVariables#permit` against an explicit allowlist, `machine.environment` has no such filtering, so any key (including `BASH_ENV`) set there flows straight to `Command#unbundled_env` and `PTY.spawn`.

### Finding Description
The broken binding: the code implicitly assumes `keys(machine_env) ⊆ safe_env_keys`, but no such allowlist exists — `deploy_spec.machine_env` is unconditionally trusted. Contrast: [1](#0-0)  shows `filter_deploy_envs`/`filter_rollback_envs` explicitly calling `EnvironmentVariables.with(env).permit(...)`, and `TaskDefinition#filter_envs` does the same [2](#0-1) . But `machine_env` itself, defined as `config('machine', 'environment') || {}` [3](#0-2) , is read directly from the checked-out `shipit.yml` with no permit/allowlist call anywhere, and is merged as-is into the task's process environment: [4](#0-3) .

`DeploySpec::FileSystem` loads this YAML from the actual working directory of the task/deploy (`@app_dir` = task's `working_directory`) via `config_file_path`/`read_config` [5](#0-4) ; for a review stack that working directory is checked out from `stack.branch`, which for review stacks is set to `params.pull_request.head.ref` — i.e., the attacker's fork branch [6](#0-5) . Because `provisioning_behavior_allow_with_label` only gates whether the review stack gets created/unarchived once a label is applied [7](#0-6) , it does nothing to sanitize the content of the fork's `shipit.yml` that will subsequently be executed for every task/deploy against that stack.

The resulting env hash (with `BASH_ENV` present) is passed into `Command.new(command_line, env:, chdir:)` and merged in `unbundled_env`: `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` [8](#0-7) . `Command#parse_arguments` keeps a plain-string step as a single argument rather than splitting it into argv [9](#0-8) , and `start` invokes `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [10](#0-9) . A single-string command passed to `Process.spawn`/`PTY.spawn` is executed through `/bin/sh -c "<command>"`, so if that shell is bash (directly or as `/bin/sh` symlinked to bash), a non-interactive invocation sources the file named by `BASH_ENV` before running the step — attacker-controlled code executes on the Shipit host with the deploy user's privileges.

Exploit flow: an attacker opens a PR from their fork against a repository with `review_stacks_enabled` and `provisioning_behavior: allow_with_label`. Once the PR carries the provisioning label (either self-applied if the attacker has triage/write access, or applied by a maintainer trusting the "opt-in" gate), a `ReviewStack` is created/unarchived tracking the attacker's branch. The attacker's `shipit.yml` on that branch declares `machine: {environment: {BASH_ENV: 'evil.sh'}}` and commits an `evil.sh` payload alongside it. When any shell-interpreted step is executed for that stack (a custom task, `deploy`/`rollback` step, etc., via `Commands.for(...).perform`/`install_dependencies`), `TaskCommands#env`/`DeployCommands#env` merges `machine_env` in unfiltered, `evil.sh` is sourced by bash, and arbitrary code runs on the deploy host.

Existing guards that fail to prevent this: `EnvironmentVariables#permit` exists and is exercised for user-submitted API `env` params (`deploys_controller`, `tasks_controller` tests confirm this filtering) [11](#0-10) , but it is never applied to `machine.environment` sourced from the repository's own `shipit.yml`. The label-based provisioning gate (`allow_with_label`) is a stack-creation gate only, not an env/content sanitizer.

### Impact Explanation
Arbitrary command execution on the Shipit deploy host under the credentials/permissions of the deploy worker process — Critical RCE via `Command`/`PTY.spawn`, matching the specified impact category. Because the attacker fully controls their own PR branch's `shipit.yml` and any file content therein, this is repeatable at will for every task/deploy run against their review stack, and the blast radius includes any shared secrets/credentials accessible to the deploy host process (e.g., `GITHUB_TOKEN`, git credentials for other repos cached on the same host, `Shipit.secrets`), not just the single tenant's own environment.

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled` with `provisioning_behavior` of `allow_with_label` (or `allow_all`, which removes even the label gate) — a documented, supported configuration. The attacker needs only to open a PR from a fork and get the review-stack provisioning label applied (either via self-service label permission or a maintainer approving review-stack creation, which is the exact scenario `allow_with_label` is meant to support). No Shipit credentials, API tokens, or GitHub secrets are required. Once the label is present, the attacker fully controls the `shipit.yml` content on their own branch, making exploitation deterministic and repeatable on every task/deploy execution.

### Recommendation
Treat `machine.environment` (and any other environment-shaping keys read from repository-provided `shipit.yml`) as untrusted for stacks whose branch content is not from a trusted/maintainer-controlled source (in particular review stacks tracking fork branches). Concretely:
- Apply an explicit allowlist (similar to `EnvironmentVariables#permit`) to `machine_env`, or restrict `machine.environment` to a fixed, host-application-configured allowlist of keys that cannot include dangerous interpreter-hooking variables (`BASH_ENV`, `ENV`, `PERL5OPT`, `PYTHONSTARTUP`, `LD_PRELOAD`, `GIT_SSH_COMMAND`, etc.).
- For review stacks (or any stack whose deploy spec is sourced from an untrusted branch), only honor `machine.environment` from a trusted/cached copy of `shipit.yml` (e.g., from the base branch/merge-base) rather than the raw fork HEAD, or strip it entirely for such stacks.
- Ensure `Command` always executes steps with `Shellwords.split` argv (avoiding the implicit shell) except where a shell is explicitly required, and if a shell is required, explicitly clear dangerous interpreter env vars before spawning.

### Proof of Concept
Minitest plan (unit-level, no live GitHub):
```ruby
# test/unit/task_commands_bash_env_test.rb
test "TaskCommands#env does not allow shipit.yml machine.environment to inject BASH_ENV" do
  stack = shipit_stacks(:shipit) # simulate a review stack tracking an attacker branch
  task = shipit_tasks(:restart) # or a Task built against `stack`
  commands = TaskCommands.new(task)

  # Simulate the attacker's shipit.yml providing machine.environment
  commands.deploy_spec.stubs(:machine_env).returns('BASH_ENV' => 'evil.sh')

  env = commands.env
  # Binding under test: keys(machine_env) should be constrained by an allowlist
  assert_not env.key?('BASH_ENV'),
    "machine.environment from an untrusted shipit.yml must not set BASH_ENV in the spawned process env"
end

test "Command#start propagates arbitrary machine_env keys into PTY.spawn env" do
  command = Command.new('true', env: { 'BASH_ENV' => 'evil.sh' }, chdir: '.')
  assert_equal 'evil.sh', command.unbundled_env['BASH_ENV']
  # demonstrates the env hash handed to PTY.spawn(unbundled_env, *interpolated_arguments, chdir: ...)
  # contains the attacker-controlled key with no filtering
end
```
Both assertions currently fail against the code as written (`env.key?('BASH_ENV')` is true, and `unbundled_env['BASH_ENV']` equals `'evil.sh'`), demonstrating that no allowlist exists between the untrusted `shipit.yml` content and the spawned shell's environment.

### Citations

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
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

**File:** app/models/shipit/deploy_spec/file_system.rb (L93-107)
```ruby
      def config(*)
        @config ||= load_config
        super
      end

      def load_config
        return if config_file_path.nil?

        if !Shipit.respect_bare_shipit_file? && config_file_path.to_s.end_with?(*bare_shipit_filenames)
          return { 'deploy' => { 'pre' => [shipit_not_obeying_bare_file_echo_command, 'exit 1'] } }
        end

        config_obj = read_config(config_file_path)
        build_config(config_file_path, config_obj)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L85-93)
```ruby
          def archive?
            (repository.provisioning_behavior_allow_with_label? && !pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && pull_request_has_provisioning_label?)
          end

          def unarchive?
            (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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

**File:** lib/shipit/command.rb (L227-240)
```ruby
    def parse_arguments(arguments)
      options = {}
      args = arguments.flatten.map do |argument|
        case argument
        when Hash
          options.merge!(argument.values.first)
          argument.keys.first
        else
          argument
        end
      end

      [args.map(&:to_s), options]
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
