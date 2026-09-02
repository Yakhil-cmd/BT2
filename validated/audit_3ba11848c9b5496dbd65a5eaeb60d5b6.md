## Title
Unfiltered `machine.environment` from a fork's `shipit.yml` reaches `PTY.spawn`, allowing arbitrary environment-variable injection (e.g. `ENV`/`BASH_ENV`) into review-stack task processes - (File: app/models/shipit/deploy_spec.rb, lib/shipit/task_commands.rb, lib/shipit/command.rb)

### Summary
`DeploySpec#machine_env` returns `config('machine', 'environment')` verbatim with no key allow-listing, and `DeploySpec::FileSystem` loads this config from the checked-out branch (the fork/PR head for a `ReviewStack`). `TaskCommands#env` merges `deploy_spec.machine_env` into the process environment, which `Command#unbundled_env` merges (attacker keys win) into the hash passed to `PTY.spawn` in `Command#start`. Because a repository with `provisioning_behavior=allow_all` provisions review stacks from unprivileged fork PRs without a maintainer label/approval gate, this lets a fork author set arbitrary environment variable names/values (including `ENV`, `BASH_ENV`, `RUBYOPT`, `LD_PRELOAD`, `BUNDLE_GEMFILE`, `PATH`, etc.) for every subsequent task run on that stack.

### Finding Description
The broken binding: `TaskCommands#env` should equal `base_env.merge(stack_env).merge(fixed_task_vars).merge(task.env)` **without** attacker-controlled keys from the PR's own `shipit.yml`, but in fact it equals that plus `.merge(deploy_spec.machine_env)` where `deploy_spec.machine_env == config('machine','environment')` [1](#0-0)  read straight from the fork branch's `shipit.yml` via `DeploySpec::FileSystem#load_config`/`config_file_path` [2](#0-1) .

`TaskCommands#env` builds the process environment and merges `deploy_spec.machine_env` in after all the "trusted" fixed keys, then `@task.env` last: [3](#0-2) . This hash is passed as `env:` to `Command.new`, stored as `@env`, and in `Command#unbundled_env` it is merged **last** (i.e., it wins over `BASE_ENV` and the injected `PATH`) before being handed to `PTY.spawn`: [4](#0-3)  and [5](#0-4) .

Unlike `deploy`/`rollback` variables, which are explicitly filtered through `EnvironmentVariables#permit` against a declared variable schema (`filter_deploy_envs`/`filter_rollback_envs`, `deploy_variables`) [6](#0-5) [7](#0-6) , `machine_env` has no such filter — it is copied straight through, including in `DeploySpec::FileSystem#cacheable_config`'s `'machine' => {'environment' => discover_machine_env.merge(machine_env), ...}` [8](#0-7) .

For a `ReviewStack`, the checked-out working directory (and therefore the `shipit.yml` that `DeploySpec::FileSystem` reads) corresponds to the PR's branch, which for `provisioning_behavior=allow_all` repositories is provisioned automatically for any fork PR without requiring a trusted label [9](#0-8) . `ReviewStack#env` itself only adds PR label flags and otherwise delegates to `Stack#env`/`TaskCommands#env` [10](#0-9) , so it inherits the same unfiltered `machine.environment` merge.

Existing guards do not stop this: `filter_deploy_envs`/`filter_rollback_envs` only apply to `deploy`/`rollback` step-scoped variables entered through the UI/API, not to `machine.environment`; there is no equivalent allow-list for `machine.environment` anywhere in `DeploySpec`.

### Impact Explanation
An attacker who can open a PR against an `allow_all` repository controls the `machine.environment` map used for every task (deploy/dependency-install/etc.) run against that review stack's `PTY.spawn` invocation. This allows setting environment variables that influence subprocess/shell behavior (`PATH`, `RUBYOPT`, `BUNDLE_GEMFILE`, `LD_PRELOAD`, or shell-startup variables such as `ENV`/`BASH_ENV` that some shells source at startup), which can result in code execution on the Shipit deploy host during any command the review-stack task executes. This matches the Critical "RCE on the deploy host via `Command`/`PTY.spawn`" category since the attacker's own PR content directly determines the spawned process's environment. Blast radius is limited to the fork's own review stack/repository resources (deploy host), not cross-tenant unless the same host runs stacks for multiple repositories with shared paths/binaries.

### Likelihood Explanation
Requires the target repository to have `provisioning_behavior = allow_all` (repository-level config choice) and `review_stacks_enabled`. Given that, the attacker only needs to open a PR from a fork with a `shipit.yml` (or `.shipit/shipit.yml`) containing a `machine: {environment: {...}}` block — no elevated privileges, tokens, or webhook secrets are needed since the PR/webhook triggers stack provisioning normally. This is inexpensive and fully repeatable against any `allow_all` repository.

### Recommendation
Filter `machine.environment` the same way `deploy`/`rollback` variables are filtered: either drop/ignore `machine.environment` entirely for fork-sourced `shipit.yml` on `ReviewStack`s (i.e., only honor it from the base/trusted branch config), or require it to declare variables via `deploy_variables`-style allow-list and run it through `EnvironmentVariables#permit` before merging in `TaskCommands#env`. Additionally, ensure `Command#unbundled_env` cannot let attacker-controlled `@env` entries override sensitive/security-relevant keys (e.g., `PATH`, `RUBYOPT`, `BUNDLE_GEMFILE`, `LD_PRELOAD`, `ENV`, `BASH_ENV`).

### Proof of Concept
minitest plan (no live GitHub required):
1. In `test/models/deploy_spec_test.rb`-style setup, build a `DeploySpec::FileSystem` (or stub `DeploySpec.new`) with config `{'machine' => {'environment' => {'ENV' => '/tmp/evil.sh'}}}` and assert `deploy_spec.machine_env == {'ENV' => '/tmp/evil.sh'}`.
2. In a `TaskCommands`-level test, stub `deploy_spec` to return that spec, call `task_commands.env`, and assert `env['ENV'] == '/tmp/evil.sh'`.
3. In a `Command`-level test, build `Command.new('echo hi', env: {'ENV' => '/tmp/evil.sh'}, chdir: Dir.tmpdir)` and assert `command.unbundled_env['ENV'] == '/tmp/evil.sh'`, demonstrating the value survives into the hash passed to `PTY.spawn` in `Command#start`.

This demonstrates the binding `TaskCommands#env['ENV'] (attacker value)` reaching `Command#unbundled_env['ENV']` unfiltered, confirming the vulnerability.

### Citations

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
    end
```

**File:** app/models/shipit/deploy_spec.rb (L120-126)
```ruby
    def deploy_variables
      Array.wrap(config('deploy', 'variables')).map(&VariableDefinition.method(:new))
    end

    def default_deploy_env
      deploy_variables.map { |v| [v.name, v.default] }.to_h
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

**File:** app/models/shipit/deploy_spec/file_system.rb (L55-59)
```ruby
          'machine' => {
            'environment' => discover_machine_env.merge(machine_env),
            'directory' => directory,
            'cleanup' => true
          },
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L98-142)
```ruby
      def load_config
        return if config_file_path.nil?

        if !Shipit.respect_bare_shipit_file? && config_file_path.to_s.end_with?(*bare_shipit_filenames)
          return { 'deploy' => { 'pre' => [shipit_not_obeying_bare_file_echo_command, 'exit 1'] } }
        end

        config_obj = read_config(config_file_path)
        build_config(config_file_path, config_obj)
      end

      YAML_EXTENSIONS = ["yml", "yaml"].freeze

      def shipit_file_names_in_priority_order
        YAML_EXTENSIONS.flat_map do |ext|
          [
            "#{app_name}.#{@env}.#{ext}",
            ".shipit/#{app_name}.#{@env}.#{ext}",

            "#{app_name}.#{ext}",
            ".shipit/#{app_name}.#{ext}",

            "shipit.#{@env}.#{ext}",
            ".shipit/#{@env}.#{ext}",

            "shipit.#{ext}",
            ".shipit/shipit.#{ext}"
          ]
        end.uniq
      end

      def bare_shipit_filenames
        YAML_EXTENSIONS.flat_map do |ext|
          ["#{app_name}.#{ext}", "shipit.#{ext}", ".shipit/#{app_name}.#{ext}", ".shipit/shipit.#{ext}"]
        end.uniq
      end

      def config_file_path
        shipit_file_names_in_priority_order.each do |filename|
          path = file(filename, root: true)
          return path if path.exist?
        end

        nil
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

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
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
