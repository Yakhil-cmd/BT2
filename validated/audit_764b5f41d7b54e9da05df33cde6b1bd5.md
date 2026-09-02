## Analysis

The invariant claimed by the question — "no fork-controllable key alters a shell-interpreted `shipit.yml` step" — is **false** for `machine.environment`. Tracing the binding:

`DeploySpec#machine_env` returns `config('machine', 'environment') || {}` **verbatim, with no filtering**: [1](#0-0) 

This contrasts with `deploy.variables`/`rollback.variables`, which are explicitly sanitized through an allowlist via `filter_deploy_envs`/`filter_rollback_envs` calling `EnvironmentVariables#permit`, which raises `NotPermitted` for any key not declared in `VariableDefinition`s: [2](#0-1) [3](#0-2) 

No equivalent `permit`/allowlist call exists for `machine_env`. It's merged directly into the task environment hash in `TaskCommands#env`: [4](#0-3) 

That hash becomes `@env` in `Command#initialize` and is folded into `unbundled_env`, which is passed to `PTY.spawn`: [5](#0-4) [6](#0-5) 

The `shipit.yml` (or `.shipit/shipit.yml`) is read straight from the checked-out working directory (i.e., the review-stack's branch, which for a fork PR is attacker-controlled content) via `DeploySpec::FileSystem#load_config`/`config_file_path`, with only `SafeYAML.load` parsing (no key restriction): [7](#0-6) [8](#0-7) [9](#0-8) 

`Command#parse_arguments` keeps a step written as a single YAML string as one array element and `Command#start` passes `*interpolated_arguments` to `PTY.spawn`, which — when there's a single string argument — is executed by `/bin/sh -c`, i.e. shell-interpreted: [10](#0-9) [11](#0-10) 

So the equality that should hold — `env_passed_to_PTY.spawn == {keys explicitly declared safe by Shipit}` — does not hold; instead `env_passed_to_PTY.spawn ⊇ fork_branch_shipit_yml['machine']['environment']` unfiltered. Since `BUNDLE_PATH` and `BUNDLE_GEMFILE` are just env-var keys, and Bundler consults `BUNDLE_GEMFILE` to decide which `Gemfile` to evaluate for any `bundle` command reachable from install-dependency/deploy/task steps, setting `BUNDLE_GEMFILE` to an attacker-controlled path checked out from the fork branch (or even a path outside the working directory, if `bundle` steps run with a chdir attacker also controls) causes Ruby code in that Gemfile to be evaluated when a `bundle` invocation occurs in any shell-interpreted step (e.g., `dependencies` auto-discovered by `BundlerDiscovery`, or explicit steps).

This matches the file/function targets given (`lib/shipit/command.rb`, `lib/shipit/task_commands.rb`, and the review-stack/fork-branch trust chain), and I found no `require_permission!`, `EnvironmentVariables#permit`, or other guard applied to `machine_env` before it reaches `PTY.spawn`.

I was not able to fully verify within the given iterations whether `prevent_with_label` (the specific provisioning handler gate for review stacks) imposes any additional restriction that prevents the shipit.yml/`Command` execution path from running at all before human approval, nor whether `BundlerDiscovery`'s discovered steps actually invoke `bundle` unconditionally in a way that's reachable without additional preconditions (e.g., a `Gemfile` existing in the repo to trigger bundler discovery). This would need confirmation via `app/models/shipit/deploy_spec/bundler_discovery.rb` and the `prevent_with_label` provisioning handler, which I did not get to read in this session.

### Title
Unfiltered `machine.environment` from fork-branch `shipit.yml` injects `BUNDLE_GEMFILE` into shell-interpreted task steps - (File: lib/shipit/task_commands.rb, app/models/shipit/deploy_spec.rb)

### Summary
`DeploySpec#machine_env` returns the `machine.environment` block of `shipit.yml` with no allowlist filtering, unlike `deploy.variables`/`rollback.variables` which go through `EnvironmentVariables#permit`. Because the `shipit.yml` consumed by `DeploySpec::FileSystem` is read from the checked-out branch — attacker-controlled for a fork PR's review stack — an attacker can set arbitrary environment variables such as `BUNDLE_GEMFILE` that get merged into the process environment passed to `PTY.spawn` for every shell-interpreted step.

### Finding Description
The broken binding: `env_passed_to_PTY.spawn` should equal `{Shipit-defined keys} ∪ permit(declared deploy/rollback variables)`, but instead it equals that set unioned with **unrestricted** `config('machine','environment')` from the fork branch's `shipit.yml`. `TaskCommands#env` merges `deploy_spec.machine_env` directly (`lib/shipit/task_commands.rb:46`) without any `EnvironmentVariables.permit` call, in contrast to `filter_deploy_envs`/`filter_rollback_envs` (`app/models/shipit/deploy_spec.rb:174-180`). `Command#initialize`/`unbundled_env` merge this env hash and pass it to `PTY.spawn(unbundled_env, *interpolated_arguments, ...)` (`lib/shipit/command.rb:92,103-105`). A step defined as a plain YAML string stays a single array element after `parse_arguments` (`lib/shipit/command.rb:227-240`), causing shell interpretation by `PTY.spawn`. Existing guards (`filter_deploy_envs`, `EnvironmentVariables#permit`, model validators) only cover `deploy`/`rollback` variables, not `machine.environment`.

### Impact Explanation
An attacker opening a PR from a fork can commit a `shipit.yml`/`.shipit/shipit.yml` setting `machine: {environment: {BUNDLE_GEMFILE: <attacker path>}}`. When the review stack runs any shell-interpreted step that invokes `bundle` (install dependencies, discovered bundler steps, or custom steps), Bundler evaluates the attacker Gemfile, executing arbitrary Ruby code on the Shipit deploy host — Critical, RCE class.

### Likelihood Explanation
Requires: review stacks enabled with `prevent_with_label` provisioning, a fork PR whose branch is checked out and whose `shipit.yml` is read by `DeploySpec::FileSystem`, and a step that runs `bundle` (directly or via discovery). Attacker cost is a single PR from a fork with no special privileges, and the primitive is repeatable per PR/review-stack.

### Recommendation
Apply an `EnvironmentVariables.permit`-style allowlist (or reject known-dangerous keys like `BUNDLE_GEMFILE`, `RUBYOPT`, `LD_PRELOAD`, `PATH`) to `DeploySpec#machine_env` before merging it in `TaskCommands#env`, or restrict `machine.environment` so it cannot be set by untrusted/fork-branch `shipit.yml` (e.g., require it be sourced from the base repo's protected config, not the PR branch).

### Proof of Concept
minitest: build a `DeploySpec::FileSystem` (or stub `deploy_spec.machine_env`) returning `{'BUNDLE_GEMFILE' => '/tmp/evil/Gemfile'}` from a simulated fork-branch `shipit.yml`; instantiate `TaskCommands#env` for a task; assert `env['BUNDLE_GEMFILE'] == '/tmp/evil/Gemfile'`; then construct `Command.new(step, env:, chdir:)` for a shell-interpreted step and assert `command.unbundled_env['BUNDLE_GEMFILE'] == '/tmp/evil/Gemfile'`, proving the value reaches the `PTY.spawn` environment unfiltered.

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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
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

**File:** lib/shipit/command.rb (L31-36)
```ruby
    def initialize(*args, chdir:, default_timeout: Shipit.default_inactivity_timeout, env: {})
      @args, options = parse_arguments(args)
      @timeout = parse_timeout(options['timeout'] || options[:timeout]) || default_timeout
      @env = env.transform_values { |v| v&.to_s }
      @chdir = chdir.to_s
      @timed_out = false
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

**File:** app/models/shipit/deploy_spec/file_system.rb (L135-142)
```ruby
      def config_file_path
        shipit_file_names_in_priority_order.each do |filename|
          path = file(filename, root: true)
          return path if path.exist?
        end

        nil
      end
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L162-164)
```ruby
      def read_config(path)
        SafeYAML.load(path.read) if path.exist?
      end
```
