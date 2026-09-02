Found `build_rollback` in `app/models/shipit/deploy.rb` never filters the caller-supplied `env` through the whitelist, unlike every other task-creation path.

### Title
Unwhitelisted environment variable injection into rollback tasks bypasses `shipit.yml` variable definitions - (File: app/models/shipit/deploy.rb)

### Summary
Every other path that creates a `Task`/`Deploy` in this engine filters the caller-supplied `env` hash through the stack's whitelist of `VariableDefinition`s declared in `shipit.yml` before persisting/spawning it. `Stack#trigger_task` calls `definition.filter_envs(env)` [1](#0-0) , and `Stack#build_deploy` calls `filter_deploy_envs(env.to_h)` [2](#0-1) . However `Deploy#build_rollback` assigns `env: env.to_h` directly with no filtering step at all [3](#0-2) .

### Finding Description
The binding this breaks is: *the set of environment variable keys an actor is permitted to set (declared via `rollback.variables` / `deploy.variables` in `shipit.yml` and enforced by `Shipit::EnvironmentVariables#permit`) MUST equal the set of environment variable keys actually spawned into the rollback shell process*.

`EnvironmentVariables#permit` is the sole gatekeeper that raises `NotPermitted` for any key not present in a stack's declared `VariableDefinition`s [4](#0-3) . `DeploySpec#filter_rollback_envs` wires that gate to the rollback variable whitelist [5](#0-4) , and it is exposed on `Stack` via `delegate ... :filter_rollback_envs ... to: :cached_deploy_spec` [6](#0-5) .

`Deploy#build_rollback` never calls `filter_rollback_envs`, so the API-supplied `env` param flows unfiltered straight into the `Rollback` record's `env` column, which is later merged verbatim into the shell environment used to spawn rollback commands via `TaskCommands#env` (`.merge(@task.env)`) and ultimately `Command#start`, which does `PTY.spawn(unbundled_env, *interpolated_arguments, ...)` [7](#0-6) [8](#0-7) .

This is the direct analog of the reported bug class: two code paths are supposed to enforce the same invariant (deploy path enforces it via `filter_deploy_envs`, rollback path silently doesn't), and the unguarded path lets an attacker-controlled value cross a trust boundary it was never vetted for — here, arbitrary environment variable injection into a spawned deploy-host process, rather than a duplicated share transfer.

### Impact Explanation
Rollback tasks execute the same `rollback` shell steps as the rest of the deploy pipeline, using `PTY.spawn` with the merged environment as literal process env vars, and `Command#interpolate_environment_variables` also lets step arguments reference `$VARNAME` from this same unsanitized hash. An attacker able to trigger a rollback (e.g. through the rollback controller/API with an arbitrary `env` payload) can inject unexpected environment variables (not limited to the `rollback.variables` whitelist) into the process that executes shell commands on the deploy host. Depending on what the deploy scripts do with environment variables (e.g. `LD_PRELOAD`, `PATH`, `BUNDLE_GEMFILE`, tool-specific config vars, or interpolated `$VAR` references in shell commands), this can escalate to command execution on the deploy host — matching the "Critical - RCE on the deploy host" impact bucket in scope.

### Likelihood Explanation
Reaching `build_rollback` still requires the caller to be an authenticated/authorized Shipit actor able to trigger a rollback (via `Deploy#trigger_rollback` or the rollbacks controller/API), which is within the engine's intended actor set for this class of finding (unprivileged relative to the deploy host / shell execution, but privileged relative to Shipit's own web app), consistent with how the audit report's attacker only needed ordinary wrap/unwrap access, not admin rights on the underlying contract.

### Recommendation
In `app/models/shipit/deploy.rb`, change `build_rollback` to filter the environment through the same whitelist used elsewhere:
```ruby
env: stack.filter_rollback_envs(env.to_h),
```
mirroring `Stack#build_deploy`'s `filter_deploy_envs(env.to_h)` call, so that only variables declared in `rollback.variables` (or falling back to `deploy.variables`, per `DeploySpec#rollback_variables`) can reach the spawned process.

### Proof of Concept
1. Attacker has permission to trigger a rollback for a stack whose `shipit.yml` declares no (or a narrow) `rollback.variables` list.
2. Attacker calls the rollback trigger path with `env: { "LD_PRELOAD" => "/tmp/evil.so" }` (or any variable name not in the whitelist).
3. `Deploy#build_rollback` stores `env.to_h` unfiltered on the `Rollback` record (`app/models/shipit/deploy.rb:90-102`) — unlike `Stack#build_deploy`, which would have raised `EnvironmentVariables::NotPermitted` for the same input via `filter_deploy_envs`.
4. When the rollback task runs, `TaskCommands#env` merges `@task.env` in verbatim (`lib/shipit/task_commands.rb:33-48`), and `Command#start` spawns the shell step with that full environment (`lib/shipit/command.rb:85-101`), giving the attacker-controlled variable to every process in the rollback pipeline.

### Citations

**File:** app/models/shipit/stack.rb (L139-159)
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
```

**File:** app/models/shipit/stack.rb (L161-172)
```ruby
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

**File:** app/models/shipit/stack.rb (L527-531)
```ruby
    delegate :plugins, :task_definitions, :hidden_statuses, :required_statuses, :soft_failing_statuses,
             :blocking_statuses, :deploy_variables, :rollback_variables, :filter_task_envs, :filter_deploy_envs,
             :filter_rollback_envs, :maximum_commits_per_deploy, :pause_between_deploys, :retries_on_deploy,
             :retries_on_rollback,
             to: :cached_deploy_spec
```

**File:** app/models/shipit/deploy.rb (L90-102)
```ruby
    def build_rollback(user = nil, env: nil, force: false)
      Rollback.new(
        user_id: user&.id,
        stack_id:,
        parent_id: id,
        since_commit: stack.last_deployed_commit,
        until_commit:,
        env: env.to_h,
        allow_concurrency: force,
        ignored_safeties: force,
        max_retries: stack.retries_on_rollback
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

**File:** app/models/shipit/deploy_spec.rb (L178-180)
```ruby
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
