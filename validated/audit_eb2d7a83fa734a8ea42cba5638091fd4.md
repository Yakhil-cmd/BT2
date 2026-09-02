### Title
`machine.environment` in a fork's `shipit.yml` reaches `PTY.spawn` unfiltered, letting a PR author inject `RUBYOPT` and gain RCE on the Shipit host - (File: `app/models/shipit/deploy_spec.rb`)

### Summary
`DeploySpec#machine_env` reads `config('machine', 'environment')` straight from the checked-out `shipit.yml` with no whitelist, unlike `deploy`/`rollback` env which is passed through `EnvironmentVariables#permit`. For review stacks, `shipit.yml` is read from the working directory checked out at the PR branch's HEAD, which an unprivileged fork author fully controls. Because `prevent_with_label` auto-provisions a stack for every PR unless the opt-out label is applied, an attacker can open a PR whose `shipit.yml` sets `machine: {environment: {RUBYOPT: '-r/path/to/evil'}}`; that value flows unsanitized into `TaskCommands#env` and then into `Command#unbundled_env`, where it overrides Bundler's cleaned environment right before `PTY.spawn`.

### Finding Description
The broken binding is: the environment hash reaching `PTY.spawn` should equal `Command::BASE_ENV` (Bundler's sanitized env) for any keys Bundler intentionally clears, but instead `unbundled_env` computes `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` [1](#0-0)  — i.e., attacker-supplied `@env` entries silently override the sanitized `BASE_ENV`, including `RUBYOPT`.

Path:
1. `DeploySpec::FileSystem` loads `shipit.yml` directly from the checked-out task working directory (`config_file_path`/`load_config`/`read_config`) with no filtering of the `machine` section [2](#0-1) .
2. `DeploySpec#machine_env` returns that section verbatim: `config('machine', 'environment') || {}` [3](#0-2) .
3. `TaskCommands#env` merges `deploy_spec.machine_env` into the task environment with no whitelist check (contrast with `filter_deploy_envs`/`filter_rollback_envs`, which do call `EnvironmentVariables#permit`) [4](#0-3) [5](#0-4) .
4. Each step's `Command.new(command_line, env:, chdir:)` stores this unsanitized hash as `@env` [6](#0-5) .
5. `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` where `unbundled_env` merges `@env` on top of the Bundler-sanitized `BASE_ENV` [7](#0-6) .

Attacker's exact action: open (or update) a PR against a repository configured with `provisioning_behavior = prevent_with_label`, without applying the opt-out label, so the review stack is created and provisioned automatically for the fork branch (`stack_attributes` sets `branch: params.pull_request.head.ref`) [8](#0-7) . The PR's own `shipit.yml` includes:
```yaml
machine:
  environment:
    RUBYOPT: "-r/path/to/evil"
```
When any `tasks.<name>.steps`, `deploy`, `dependencies`, or `rollback` command later runs for that review stack (deploy, restart task, CI-triggered task, etc.), `RUBYOPT` is injected into every `ruby`/`bundle`/`rake` invocation, executing attacker code as the Shipit process user.

Existing guards do not stop this: `EnvironmentVariables#permit` (the whitelist mechanism) is used for `deploy`/`rollback`/task-trigger `env` params [9](#0-8) , but `machine_env` bypasses it entirely — it is documented as a legitimate `shipit.yml` feature (`machine.environment`) with no expectation that fork-controlled files are less trusted, and there is no separate filtering for review stacks.

### Impact Explanation
This is Critical: Remote Code Execution on the Shipit deploy host. Any command inheriting the environment that Shipit spawns (`ruby`, `bundle`, `rake`, or any script that respects `RUBYOPT`/similar interpreter env vars) will execute attacker-supplied code with the privileges of the Shipit worker process. This is repeatable per-PR and per-review-stack; the blast radius is scoped to whichever repository enables review stacks with `prevent_with_label` (or `allow_all`, which has the same unsanitized `machine_env` path), but grants the attacker code execution on shared deploy infrastructure, which can pivot into other stacks/secrets (`GITHUB_TOKEN`, deploy credentials) that live on the same host.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled with `provisioning_behavior` set to `prevent_with_label` (or `allow_all`/`allow_with_label`, all of which expose the same unfiltered `machine_env`). No maintainer approval, label application by a privileged party, or secrets are required — the attacker simply opens a fork PR with a malicious `shipit.yml` and (for `prevent_with_label`) does nothing further, since the stack is auto-provisioned. Attacker cost is minimal: one PR, one commit. This is fully repeatable and does not require any privileged GitHub role, Shipit session, or API token.

### Recommendation
Sanitize `machine.environment` the same way `deploy`/`rollback` variables are sanitized: require an explicit, maintainer-defined whitelist of permitted variable names (configured at the Shipit `Repository`/`Stack` level, not inside the untrusted `shipit.yml`), and reject or strip any keys not on that whitelist — in particular block known dangerous interpreter-hijacking variables (`RUBYOPT`, `RUBYLIB`, `BUNDLE_GEMFILE`, `LD_PRELOAD`, `PATH`, etc.) unconditionally regardless of whitelist. Additionally, ensure `Command#unbundled_env` cannot let `@env` override the deliberately-cleared Bundler keys in `BASE_ENV`.

### Proof of Concept
minitest plan (`test/lib/shipit/task_commands_test.rb` or `test/models/deploy_spec_test.rb`):
```ruby
test "#env does not let machine.environment override RUBYOPT for review stack tasks" do
  stack = shipit_stacks(:review_stack) # ReviewStack, provisioning_behavior: prevent_with_label
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  deploy_spec = stub(machine_env: { 'RUBYOPT' => '-r/path/to/evil' }, dependencies_steps!: [], clear_working_directory?: true)
  commands = Shipit::TaskCommands.new(task)
  commands.stubs(:deploy_spec).returns(deploy_spec)

  env = commands.env
  # Binding under test, before fix: env['RUBYOPT'] == '-r/path/to/evil' (attacker controlled)
  # Expected invariant: env['RUBYOPT'] must be nil / not attacker-settable
  assert_nil env['RUBYOPT'], "fork-controlled machine.environment must not inject RUBYOPT"

  command = Shipit::Command.new('ruby -e puts', env:, chdir: '.')
  spawned_env = command.unbundled_env
  # Binding under test at the PTY.spawn boundary
  assert_nil spawned_env['RUBYOPT'], "RUBYOPT reaching PTY.spawn must remain nil/sanitized"
end
```
This test demonstrates that, as currently implemented, `env['RUBYOPT']` and `spawned_env['RUBYOPT']` equal the attacker's `'-r/path/to/evil'` value rather than `nil`, proving the divergence from the intended invariant.

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

**File:** app/models/shipit/deploy_spec/file_system.rb (L98-107)
```ruby
      def load_config
        return if config_file_path.nil?

        if !Shipit.respect_bare_shipit_file? && config_file_path.to_s.end_with?(*bare_shipit_filenames)
          return { 'deploy' => { 'pre' => [shipit_not_obeying_bare_file_echo_command, 'exit 1'] } }
        end

        config_obj = read_config(config_file_path)
        build_config(config_file_path, config_obj)
      end
```

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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```
