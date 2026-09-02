## Analysis

The claimed binding: the attacker asserts that `PATH` set anywhere in an attacker-influenced `env` hash survives into the process executed by `PTY.spawn`, because `Command#unbundled_env` merges the caller-supplied `@env` *last*.

Tracing `Command#unbundled_env`:
```
BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
``` [1](#0-0) 
Since `@env.stringify_keys` is merged last, any `PATH` key present in `@env` fully overrides the computed `Shipit.shell_paths:...:ENV['PATH']` value, and this result is passed directly to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`. [2](#0-1) 

The relevant question is whether `@env` can actually contain a `PATH` key for a review-stack task. Tracing `TaskCommands#env`:
```ruby
def env
  super
    .merge(@stack.env)
    .merge(...)
    .merge(deploy_spec.machine_env)
    .merge(@task.env)
end
``` [3](#0-2) 

- `deploy_spec.machine_env` returns `config('machine', 'environment') || {}` straight from the repo's `shipit.yml`, **with no key allowlist/filter** applied. [4](#0-3) 
- `@task.env`, in contrast, is populated via `Stack#trigger_task`/`build_deploy`, which explicitly filters through `EnvironmentVariables#permit(variable_definitions)` against a task/deploy-variable allowlist before persisting `task.env`. [5](#0-4) [6](#0-5) 

So `EnvironmentVariables#permit` protects `@task.env`, but it does **not** protect `deploy_spec.machine_env`. For a `ReviewStack`, `deploy_spec` is built from the fork's own checked-out `shipit.yml` (`DeploySpec::FileSystem.new(@task.working_directory, @stack)`), and for a repo configured with `provisioning_behavior: allow_with_label`, that `shipit.yml` content is exactly what the unprivileged PR author controls in their fork/branch. [7](#0-6) 

This means an attacker opening a PR (with the required provisioning label) can add to their fork's `shipit.yml`:
```yaml
machine:
  environment:
    PATH: "/tmp/attacker-bin:/usr/bin:/bin"
```
This value flows unfiltered through `machine_env` → merged into `TaskCommands#env` → passed as `env:` to `Command.new(step, env:, chdir: ...)` for every shell-interpreted step (`deploy`, `rollback`, `fetch`, custom `tasks`, `dependencies`) → `Command#unbundled_env` overrides the safe `PATH` → `PTY.spawn` executes the step with attacker PATH. Any bare command name referenced in a step (e.g. `bundle`, `cap`, `git`... though `git` calls use the `Commands#git` helper with its own env merge order — worth noting `StackCommands#env` also merges `@stack.env`, not `machine_env`, so `git` calls are less exposed than task/deploy `perform` steps) resolves to the attacker's binary placed in the checked-out working directory or `/tmp`.

None of the existing guards intercept this: `EnvironmentVariables#permit` is applied to `@task.env`/`deploy.env` but never to `deploy_spec.machine_env`; there is no allowlist in `Command#unbundled_env` rejecting dangerous keys like `PATH`, `LD_PRELOAD`, `RUBYOPT`, `BUNDLE_GEMFILE`, etc.

## Verdict

This is a real, reachable divergence: `machine.environment` from a fork-controlled `shipit.yml`, unfiltered by `EnvironmentVariables#permit`, can inject a `PATH` (or other dangerous interpreter-affecting variable) that overrides Shipit's safe `PATH` in `Command#unbundled_env`, and is spawned via `PTY.spawn` for every step of a `allow_with_label` review stack task. This matches the Critical RCE class described.

### Title
Unfiltered `shipit.yml` `machine.environment` lets a fork PR override `PATH` reaching `PTY.spawn` - (File: lib/shipit/task_commands.rb, lib/shipit/command.rb)

### Summary
`TaskCommands#env` merges `deploy_spec.machine_env` — sourced directly from the fork's own `shipit.yml` for `allow_with_label` review stacks — without passing it through `EnvironmentVariables#permit`. `Command#unbundled_env` merges the caller's `@env` last, so an attacker-supplied `PATH` key fully overrides the computed safe `PATH` before `PTY.spawn` executes shell-interpreted task/deploy/rollback/fetch steps.

### Finding Description
The broken invariant: `Command#unbundled_env` is expected to equal `Shipit.shell_paths + ENV['PATH']` merged with only *whitelisted* task/deploy variables; in reality it equals `BASE_ENV.merge(safe PATH).merge(@env)` where `@env` includes `deploy_spec.machine_env`, an unfiltered pass-through of the repository's `shipit.yml` `machine.environment` key (`app/models/shipit/deploy_spec.rb:69-71`). For a `ReviewStack` under `provisioning_behavior: allow_with_label`, `deploy_spec` is instantiated from the checked-out fork branch (`TaskCommands#deploy_spec`, `lib/shipit/task_commands.rb:13-15`), meaning the attacker's own PR content defines `machine_env`. `TaskCommands#env` merges this unfiltered hash into the final environment (`lib/shipit/task_commands.rb:33-48`), which is then passed to every `Command.new(step, env:, chdir:)` used for `install_dependencies`/`perform` steps (`lib/shipit/task_commands.rb:17-27`). `Command#unbundled_env` merges `@env.stringify_keys` last, letting a `PATH` key in `machine_env` fully override the safe `PATH` (`lib/shipit/command.rb:103-105`), and `Command#start` spawns the shell-interpreted step string via `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` (`lib/shipit/command.rb:92`). Existing guards (`EnvironmentVariables#permit`) are applied only to `@task.env`/deploy `env` params submitted through controllers (`app/models/shipit/stack.rb:139-172`, `lib/shipit/environment_variables.rb:13-18`) — they never touch `machine_env`, leaving it as an unguarded injection point.

### Impact Explanation
An attacker who can label their own fork PR under `allow_with_label` (an unprivileged action) achieves RCE on the Shipit deploy host: any bare command invoked by a `deploy`/`rollback`/`fetch`/custom task step (e.g. `bundle`, `cap`, project scripts) resolves through the attacker-poisoned `PATH` to an attacker-controlled binary placed in the checked-out working directory, executing with the full task environment (including `GITHUB_TOKEN`, `GIT_COMMITTER_*`, etc.). This is repeatable per PR/task run and scoped to the repository owning the review stack, but since Shipit deploy hosts frequently run multiple stacks/repos with shared host-level access and credentials, this can escalate into cross-tenant compromise of the deploy host itself — matching the Critical RCE class.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled with `provisioning_behavior: allow_with_label`, and the attacker's PR must carry the provisioning label (attacker-controllable if they can self-label, or requires a maintainer to apply the label depending on repo config — this is the main gating factor, but is explicitly the scope of Q1818). Attacker cost is minimal: editing `shipit.yml` in their own fork/branch and opening a PR. No secrets or elevated Shipit roles are required. Highly feasible and repeatable against any repo so configured.

### Recommendation
Filter `deploy_spec.machine_env` (and any other free-form `shipit.yml`-derived env, e.g. task `variables` defaults) through an allowlist mechanism before merging into `TaskCommands#env`/`StackCommands#env`, and explicitly strip/deny security-sensitive keys (`PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `RUBYOPT`, `BUNDLE_GEMFILE`, `IFS`, etc.) in `Command#unbundled_env` regardless of source, e.g. by merging `@env` before computing `PATH` rather than after, or by explicitly re-asserting `'PATH' => safe_path` as the final merge key.

### Proof of Concept
Minitest plan (`test/unit/task_commands_test.rb` or `test/unit/command_test.rb`):
```ruby
test "machine_env PATH from shipit.yml overrides the safe PATH reaching PTY.spawn" do
  stack = shipit_stacks(:review_stack) # allow_with_label review stack fixture
  task  = shipit_tasks(:some_pending_task_on_review_stack)

  deploy_spec = stub(
    dependencies_steps!: [],
    machine_env: { 'PATH' => '/tmp/attacker-bin' }, # attacker-controlled shipit.yml content
    clear_working_directory?: true
  )
  commands = TaskCommands.new(task)
  commands.stubs(:deploy_spec).returns(deploy_spec)

  step_command = commands.perform.first
  # Binding under test: safe_path == step_command.unbundled_env['PATH']
  refute_equal "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}", step_command.unbundled_env['PATH']
  assert_equal '/tmp/attacker-bin', step_command.unbundled_env['PATH']
end
```
This demonstrates that the `PATH` value passed to `PTY.spawn` (via `Command#unbundled_env`) diverges from the intended safe value once `machine_env` supplies a `PATH` key, with no `EnvironmentVariables#permit` step ever consulted for `machine_env`.

### Citations

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

**File:** lib/shipit/task_commands.rb (L13-15)
```ruby
    def deploy_spec
      @deploy_spec ||= DeploySpec::FileSystem.new(@task.working_directory, @stack)
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

**File:** app/models/shipit/stack.rb (L139-172)
```ruby
    def trigger_task(definition_id, user, env: nil, force: false)
      definition = find_task_definition(definition_id)
      env = env.to_h

      definition.variables_with_defaults.each do |variable|
        env[variable.name] ||= variable.default
      end

      commit = last_deployed_commit.presence || commits.first
      task = tasks.create(
        user_id: user.id,
        definition:,
        until_commit_id: commit.id,
        since_commit_id: commit.id,
        env: definition.filter_envs(env),
        allow_concurrency: definition.allow_concurrency? || force,
        ignored_safeties: force
      )
      task.enqueue
      task
    end

    def build_deploy(until_commit, user, env: nil, force: false, allow_concurrency: force)
      since_commit = last_deployed_commit.presence || commits.first
      deploys.build(
        user_id: user.id,
        until_commit:,
        since_commit:,
        env: filter_deploy_envs(env.to_h),
        allow_concurrency:,
        ignored_safeties: force || !until_commit.deployable?,
        max_retries: retries_on_deploy
      )
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
