### Title
Unfiltered `shipit.yml` `machine.environment` env vars (e.g. `RUBYOPT`/`BASH_ENV`) reach spawned `ruby`/`bundle` dependency steps on `allow_all` review stacks - ([File: lib/shipit/task_commands.rb])

### Summary
`TaskCommands#env` merges `deploy_spec.machine_env` directly into the command environment with no allow-list, unlike deploy/task/rollback envs which are always passed through `EnvironmentVariables#permit`. On a repository configured with `provisioning_behavior: allow_all`, the `shipit.yml` (and any committed file) used to compute `machine_env` is read from the attacker's own fork/PR branch, letting an unprivileged PR author inject arbitrary environment variables (loader variables such as `RUBYOPT`/`BASH_ENV`) into the `ruby`/`bundle` dependency step spawned by `Command#start`.

### Finding Description
The broken binding: `TaskCommands#env` should equal `Shipit.env ∪ @stack.env ∪ {fixed keys} ∪ EnvironmentVariables.permit(deploy_spec.machine_env, allow_list) ∪ EnvironmentVariables.permit(@task.env, task_variables)`. In reality it equals: [1](#0-0) 

`.merge(deploy_spec.machine_env)` is applied with **no `EnvironmentVariables.permit` call**, unlike every other user-influenced env source in the codebase (`filter_deploy_envs`, `filter_rollback_envs`, `TaskDefinition#filter_envs`) which all route through the allow-list in `lib/shipit/environment_variables.rb`: [2](#0-1) 

`deploy_spec.machine_env` is defined as: [3](#0-2) 

i.e. `config('machine', 'environment') || {}` — a raw pass-through of the `machine.environment` key from the checked-out `shipit.yml`, confirmed unfiltered by `README.md:723-725` ("All the content of the shipit.yml machine.environment key"). For a review stack, that `shipit.yml` is read from the working directory that was checked out from the attacker's PR commit (`TaskCommands#checkout` / `DeploySpec::FileSystem.new(@task.working_directory, @stack)`), which is fully attacker-controlled content.

`Command#unbundled_env` performs no key filtering either: [4](#0-3) 

and `Command#start` spawns the process with this merged hash directly: [5](#0-4) 

Exploit flow: attacker opens a PR against a repository with `review_stacks_enabled: true` and `provisioning_behavior: allow_all` (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:65-70` — `provision?` is true with no label/permission check for `allow_all`). The PR's fork contains a `shipit.yml` with:
```yaml
machine:
  environment:
    RUBYOPT: "-r./evil.rb"
```
plus a committed `evil.rb` containing attacker code. When the review stack provisions and the task execution strategy runs `install_dependencies` (`TaskCommands#install_dependencies` building `bundle install`/`ruby` steps from `dependencies_steps!`), `RUBYOPT` is present in the spawned environment. Ruby (invoked to run `bundle`) honours `RUBYOPT` and `-r` loads and executes `evil.rb` at interpreter startup, achieving code execution on the Shipit deploy host under the Shipit worker's privileges — before any allow-list filtering of "dangerous" variables can apply, because none is ever invoked on this path.

Existing guards (`EnvironmentVariables#permit`, `filter_deploy_envs`, `TaskDefinition#filter_envs`, controller `params.permit`) all guard **user/API-supplied `env` hashes**, not `machine_env` sourced from the deploy spec, so they never intercept this path.

### Impact Explanation
Arbitrary code execution on the Shipit deploy host, achievable purely by opening a pull request against a repository configured with `allow_all` review stacks — no label, no maintainer approval, no Shipit credentials required. This is repeatable against any repository with this (documented as "most likely" recommended) configuration, and grants the attacker whatever privileges the Shipit worker process holds, including access to `GITHUB_TOKEN`/deploy secrets exposed to the task environment. This matches the Critical — RCE-on-deploy-host category.

### Likelihood Explanation
Preconditions: the target repository must have Review Stacks enabled with `provisioning_behavior: allow_all` (documented in `docs/review_stacks.md` as the common/recommended setting). No other privilege is required — any GitHub user able to open a PR against such a repo (including from a fork, since GitHub allows PRs from forks) can trigger this. Attacker cost is minimal: add two lines to `shipit.yml` plus a small ruby file, no secrets or tokens needed.

### Recommendation
Filter `deploy_spec.machine_env` (and any other config-derived env) through the same `EnvironmentVariables.permit` allow-list mechanism used for deploy/rollback/task envs, or maintain an explicit deny-list of loader/interpreter-influencing variable names (`RUBYOPT`, `RUBYLIB`, `BASH_ENV`, `ENV`, `PERL5OPT`, `PYTHONSTARTUP`, `LD_PRELOAD`, `GEM_PATH`, etc.) that can never be set via `machine.environment` regardless of trust level, especially for review stacks whose `shipit.yml` originates from unprivileged, un-reviewed PR branches.

### Proof of Concept
Minitest plan (`test/unit/task_commands_test.rb` or extending `test/unit/deploy_commands_test.rb`):
```ruby
test "#install_dependencies does not leak dangerous loader variables from machine_env" do
  @deploy_spec.stubs(:machine_env).returns('RUBYOPT' => '-r./evil.rb')
  command = @commands.install_dependencies.first
  # Binding under test: command.env['RUBYOPT'] should be nil (filtered) not '-r./evil.rb' (leaked)
  assert_nil command.env['RUBYOPT'], "machine_env should be filtered before reaching the spawned bundle/ruby process"
end
```
Before the fix, this assertion fails because `TaskCommands#env` merges `deploy_spec.machine_env` unfiltered (`lib/shipit/task_commands.rb:46`), demonstrating `command.env['RUBYOPT'] == '-r./evil.rb'` reaches `Command#unbundled_env` and thus `PTY.spawn`.

### Citations

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

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
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
