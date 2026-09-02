### Title
Untrusted `machine.environment` from PR-sourced `shipit.yml` overrides `PATH`/`BUNDLE_PATH` in the deploy environment, enabling PATH-hijack RCE - (File: lib/shipit/task_commands.rb, lib/shipit/command.rb)

### Summary
`TaskCommands#env` merges `deploy_spec.machine_env` (parsed unfiltered from the repository's `shipit.yml`) after Shipit's own internally-set variables such as `BUNDLE_PATH`, and `Command#unbundled_env` merges `@env` (which includes `machine_env`) after the `PATH` it builds from `Shipit.shell_paths`. Because review-stack deploy specs are loaded via `DeploySpec::FileSystem` from the checked-out PR branch, an attacker-controlled `shipit.yml` can redefine `PATH` or `BUNDLE_PATH`, and that value wins in the final environment handed to `PTY.spawn`.

### Finding Description
The broken binding: intended equality is `unbundled_env['PATH'] == Shipit.shell_paths.join(':') + ':' + ENV['PATH']` for every task/deploy command; actual result after the merge chain is `unbundled_env['PATH'] == @env['PATH']` whenever `@env` (i.e. `deploy_spec.machine_env` or `@task.env`) defines `PATH`.

Code path:
- `DeploySpec#machine_env` reads `config('machine', 'environment')` directly from the parsed YAML with no key allowlist [1](#0-0) .
- `DeploySpec::FileSystem#load_config` parses `shipit.yml` (or `.shipit/shipit.yml`) straight off `@app_dir`, which is `@task.working_directory`, i.e. the checked-out commit of the task (for review-stack builds, this is the PR branch content) [2](#0-1) [3](#0-2) .
- `TaskCommands#env` builds the env by merging, in order: `super`, `@stack.env`, an internal hash including `'BUNDLE_PATH' => Rails.root.join(...)`, then `.merge(deploy_spec.machine_env)`, then `.merge(@task.env)` — so `machine_env` (attacker content) overrides the `BUNDLE_PATH` Shipit just set, and nothing here constrains which keys `machine_env` may contain [4](#0-3) .
- `Command#unbundled_env` computes `BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)` — `@env` is merged last, so if `machine_env` (folded into `@env` upstream) contains a `PATH` key, it silently overrides Shipit's own PATH before `PTY.spawn(unbundled_env, *interpolated_arguments, ...)` executes [5](#0-4) [6](#0-5) .

Existing guards do not stop this: `EnvironmentVariables#permit` (used via `filter_deploy_envs`/`filter_rollback_envs`) only allowlists `deploy_variables`/`rollback_variables` declared under `deploy.variables`/`rollback.variables` in the spec [7](#0-6) [8](#0-7) ; `machine_env` is never passed through `permit` and has no key-name restriction. There is no validation elsewhere in `Stack`, `Repository`, or the `DeploySpec` schema restricting the names or values allowed under `machine.environment`.

Attacker exact input: a pull request from an attacker-controlled fork/branch that adds/modifies `shipit.yml` with:
```yaml
machine:
  environment:
    PATH: "/tmp/evil:${PATH}"
```
When a review stack (or any deploy that loads spec from that branch/commit) runs any `deploy_steps`/`dependencies_steps` command, `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` with the poisoned `PATH`, so any bare-name binary invoked by the deploy/dependency steps (e.g. `bundle`, `git`, `sh`) can resolve to an attacker-planted binary at `/tmp/evil`, achieving command execution on the deploy host with the privileges of the Shipit worker process.

### Impact Explanation
This is Critical: RCE on the deploy host via `Command`/`PTY.spawn`. An attacker with only PR-authoring/fork-push ability (as scoped) can shadow `PATH` (and other internally-managed variables like `BUNDLE_PATH`, which controls where `bundle install` looks/writes gems) for their own stack's deploy/review commands, letting subsequent `deploy_steps` in the same repo's `shipit.yml`, or standard tool invocations (bundler, sed, git), execute attacker binaries instead of the intended ones. Blast radius is the Shipit worker host and any credentials/state accessible during that task's execution (SSH keys, GITHUB_TOKEN if exported into the environment, other repos' git checkouts on the same host). It is repeatable per PR/per task run.

### Likelihood Explanation
Preconditions are met by an ordinary attacker per the threat model: they need only to open (or push to) a PR that modifies `shipit.yml`'s `machine.environment` in a repo where review-stacks or task-spec loading uses the PR branch content (`DeploySpec::FileSystem` loads from `@task.working_directory`, the checked-out task commit). No secrets, no maintainer approval, and no privileged Shipit role are required to have the spec parsed and merged into the environment — this is standard review-stack behavior already implemented in the engine. Feasibility is high and directly demonstrable via unit tests on `DeploySpec`, `TaskCommands#env`, and `Command#unbundled_env` without any live GitHub interaction.

### Recommendation
Do not let `machine_env` (or any part of a repo-controlled `DeploySpec`) override Shipit-managed environment keys. Concretely:
- In `TaskCommands#env`, merge `deploy_spec.machine_env` and `@task.env` *before* Shipit's own reserved keys (`BUNDLE_PATH`, `SHIPIT_USER`, `GIT_COMMITTER_*`, etc.), or explicitly strip reserved keys from `machine_env`/`@task.env` prior to merging.
- In `Command#unbundled_env`, reject or strip a `PATH` key (and any other Shipit-reserved var) from `@env` before merging over `BASE_ENV`, so the computed `PATH` from `Shipit.shell_paths`/`ENV['PATH']` cannot be overridden by user-supplied env.
- Consider an explicit denylist/allowlist for `machine.environment` similar to `EnvironmentVariables#permit` used for `deploy.variables`.

### Proof of Concept
Add a minitest to `test/lib/shipit/task_commands_test.rb` (or `test/unit/command_test.rb`):

```ruby
test "PATH set via machine_env in shipit.yml overrides Shipit's own PATH in unbundled_env" do
  stack = shipit_stacks(:shipit)
  task = shipit_tasks(:shipit)
  commands = Shipit::TaskCommands.new(task)

  deploy_spec = mock('deploy_spec')
  deploy_spec.stubs(:machine_env).returns('PATH' => '/tmp/evil:$PATH')
  deploy_spec.stubs(:directory).returns(nil)
  commands.stubs(:deploy_spec).returns(deploy_spec)

  env = commands.env
  command = Shipit::Command.new('true', env: env, chdir: '/tmp')

  expected_shipit_path = "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"

  # Binding claimed broken: unbundled_env['PATH'] should equal Shipit's computed PATH,
  # not the attacker-controlled value.
  refute_equal expected_shipit_path, command.unbundled_env['PATH']
  assert_equal '/tmp/evil:$PATH', command.unbundled_env['PATH']
end
```

This demonstrates that the attacker's `machine.environment.PATH` value (sourced from `shipit.yml` on the PR branch) reaches `Command#unbundled_env` and wins over `Shipit.shell_paths`-derived `PATH`, confirming the divergence with no live GitHub or privileged access required.

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

**File:** app/models/shipit/deploy_spec/file_system.rb (L16-21)
```ruby
      def initialize(app_dir, stack)
        @app_dir = Pathname(app_dir)
        @env = stack.environment
        @stack = stack
        super(nil)
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

**File:** lib/shipit/command.rb (L92-92)
```ruby
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
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
