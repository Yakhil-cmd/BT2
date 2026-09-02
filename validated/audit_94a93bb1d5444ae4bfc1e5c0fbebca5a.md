### Title
Attacker-controlled `machine.environment` in a fork's `shipit.yml` reaches `PTY.spawn` unfiltered, enabling `RUBYLIB`/env-based RCE on review-stack tasks - (File: `app/models/shipit/deploy_spec.rb`, `lib/shipit/task_commands.rb`, `lib/shipit/command.rb`)

### Summary
`DeploySpec#machine_env` reads the `machine.environment` key directly out of the checked-out `shipit.yml` with no allowlist, unlike `deploy_variables`/`rollback_variables`/task `variables`, which are always passed through `EnvironmentVariables#permit`. For review stacks (including `allow_with_label`), the `shipit.yml` used to build the `DeploySpec::FileSystem` is read from the attacker's own PR branch checkout, so the attacker fully controls this hash, including a key like `RUBYLIB`.

### Finding Description
The broken binding: `TaskCommands#env` merges `deploy_spec.machine_env` unfiltered into the environment used to build each `Command`, i.e. it violates the invariant "no fork-controllable environment key alters any interpreter/tool the deploy spawns."

- `TaskCommands#env` merges `.merge(deploy_spec.machine_env)` before `.merge(@task.env)` [1](#0-0) .
- `DeploySpec#machine_env` is simply `config('machine', 'environment') || {}` — raw values from the parsed shipit.yml, with no call to `EnvironmentVariables.with(...).permit(...)` anywhere in its definition [2](#0-1) . Contrast this with `filter_deploy_envs`/`filter_rollback_envs`/`TaskDefinition#filter_envs`, which all explicitly call `EnvironmentVariables.with(env).permit(...)` against a declared variable whitelist [3](#0-2) [4](#0-3) .
- `DeploySpec::FileSystem` loads `shipit.yml` (or `.shipit/shipit.yml`) straight from the task's working directory, which for a task is the git checkout of the commit under review [5](#0-4) [6](#0-5) . For a review stack, that working directory is checked out from the PR's head commit (the attacker's fork), so the attacker fully controls the YAML content, including `machine: {environment: {RUBYLIB: "/tmp/evil"}}`.
- The merged env eventually reaches `Command#start`, which does `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`; `unbundled_env` merges `BASE_ENV` with `@env.stringify_keys`, with no key filtering at all [7](#0-6) .
- `Command#parse_arguments`/`interpolated_arguments` keeps a step defined as a single string, so `PTY.spawn` executes it via `/bin/sh -c "<step>"` — a shell-interpreted step. Any step that shells out to `ruby` (directly, via a rake task, `bundle exec` wrapper scripts, etc.) will inherit the attacker's `RUBYLIB`, causing arbitrary attacker-authored Ruby code to be `require`d and executed on the Shipit deploy host.
- None of the request-time guards apply here: `EnvironmentVariables#permit` is never invoked for `machine_env`; the value never passes through the `stacks`/task-trigger API params path (so `assert_json 'message', 'Variables ... have not been whitelisted'` style protections in `test/controllers/api/tasks_controller_test.rb` don't apply); webhook signature verification and `provisioning_behavior` gating (`allow_with_label`) only decide *whether* a review stack gets provisioned and its `shipit.yml` executed — they don't sanitize the contents of that `shipit.yml`.

### Impact Explanation
Once an attacker opens (or updates) a PR with the provisioning label set (satisfying `allow_with_label`), Shipit will clone the fork's commit, load its `shipit.yml`, and execute `dependencies_steps`, `deploy_steps`, or custom tasks with the attacker's `machine.environment` merged into the process env for every `Command` built by `TaskCommands` (see `install_dependencies`/`perform` at [8](#0-7) ). This is Remote Code Execution on the Shipit deploy host, in the process context that already carries `GITHUB_TOKEN` and other deploy-time secrets exposed via `Commands#base_env` [9](#0-8) , matching the Critical/RCE class described in the rules. This is repeatable by any unprivileged fork owner against any repository with review stacks + `allow_with_label` enabled, without any secrets or privileged role.

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled` and `provisioning_behavior` set to `allow_with_label` (or `allow_all`) — a common, documented setup [10](#0-9) . The attacker only needs to open a PR from their own fork with the provisioning label applied (which they can add themselves if they're the PR author, per the labeled/unlabeled/opened handlers) and include a crafted `shipit.yml`/`.shipit/shipit.yml` in that branch. No Shipit credentials, GitHub App keys, or maintainer status required. Exploitation additionally requires that at least one shell-interpreted step in the discovered/`shipit.yml`-declared pipeline invokes an interpreter sensitive to the injected variable (e.g., `ruby`, `bundle exec` wrapper scripts sensitive to `RUBYLIB`), which is realistic for most Ruby-based deploy pipelines that this engine is built to support, but is a slightly narrower condition than "always exploitable regardless of stack language" (it is directly exploitable for any Ruby-based project, and analogous unfiltered-env vectors, e.g. `PYTHONPATH`/`NODE_OPTIONS`/`LD_PRELOAD`, extend it to essentially any stack).

### Recommendation
Sanitize `machine.environment` the same way `deploy_variables`/`rollback_variables`/task `variables` are sanitized: require it to be declared/allowlisted by the deploy spec, or restrict it to a repository-admin-controlled configuration channel (e.g. Shipit repository settings) rather than the arbitrary fork-controlled `shipit.yml`, especially for review-stack provisioning contexts. Additionally, deny well-known dangerous variable names (`RUBYLIB`, `RUBYOPT`, `PYTHONPATH`, `LD_PRELOAD`, `NODE_OPTIONS`, `GEM_PATH`, `BUNDLE_GEMFILE`, etc.) from ever being set via untrusted `shipit.yml`/task-level env, and consider not shell-interpreting single-string steps (use `Shellwords.split` + array-form `PTY.spawn` for that class of attacker-influenced steps), or explicitly stripping/normalizing such interpreter-hijacking env keys in `Command#unbundled_env` before merging `@env`.

### Proof of Concept
Minitest test plan (no live GitHub required):
1. In `test/models/deploy_spec_test.rb` style, stub `DeploySpec::FileSystem#load_config` (or write a fixture `shipit.yml`) to return `'machine' => { 'environment' => { 'RUBYLIB' => '/tmp/attacker_pwn' } }`, matching how a fork-controlled `shipit.yml` would be parsed.
2. Assert `spec.machine_env == { 'RUBYLIB' => '/tmp/attacker_pwn' }` — showing no filtering occurred (equality: `spec.machine_env` should equal `EnvironmentVariables.with('RUBYLIB' => '/tmp/attacker_pwn').permit(spec.deploy_variables)` would raise `NotPermitted` if it went through the whitelist path, proving the divergence).
3. Build a `Shipit::ReviewStack`/`Shipit::Task` fixture whose `stack.cached_deploy_spec` is this spec, instantiate `TaskCommands.new(task)`, and assert `commands.env['RUBYLIB'] == '/tmp/attacker_pwn'`.
4. Call `commands.perform.first` (or `install_dependencies.first`) to get a `Command`, and assert `command.env['RUBYLIB'] == '/tmp/attacker_pwn'` and that `command.unbundled_env['RUBYLIB'] == '/tmp/attacker_pwn'`.
5. Optionally run the command with a step like `'ruby -e "require %q(pwn)"'` against a temp `RUBYLIB` directory containing a `pwn.rb` that writes a marker file, and assert the marker file was created after `command.run`, proving code execution via the unfiltered env var.

### Citations

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

**File:** app/models/shipit/deploy_spec/file_system.rb (L16-21)
```ruby
      def initialize(app_dir, stack)
        @app_dir = Pathname(app_dir)
        @env = stack.environment
        @stack = stack
        super(nil)
      end
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L98-143)
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

**File:** lib/shipit/command.rb (L92-105)
```ruby
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

**File:** lib/shipit/commands.rb (L37-50)
```ruby
    def base_env
      @base_env ||= begin
        env = Shipit.env.merge(
          'GITHUB_DOMAIN' => github.domain,
          'GITHUB_TOKEN' => github.token
        )

        if Shipit.use_git_askpass?
          env['GIT_ASKPASS'] = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s
        end

        env
      end
    end
```

**File:** docs/review_stacks.md (L15-21)
```markdown
# Configuring Review Stack behavior

shipit-engine support three distinct behaviors for determining which Pull Requests should be considered for Review Stack creation.

1. "Allow All" - shipit-engine will create a Review Stack for every new Pull Requests.
1. "Allow With Label" - when creating or updating a Pull Request, the user must add a label matching the `Shipit::Repository`'s "provisioning_label" attribute in order for shipit-engine to dynamically create/manage a Review Stack - an opt-in strategy.
1. "Prevent With Label" - when creating or updating a Pull Request, the user must add a label matching the `Shipit::Repository`'s "provisoining_label" attribute in order to **prevent** shipit-engine from dynamically creating/managing a Review Stack - an opt-out strategy.
```
