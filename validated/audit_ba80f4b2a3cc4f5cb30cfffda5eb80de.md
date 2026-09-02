### Title
Rollback Environment Variables Bypass Whitelist Enforcement Applied to Deploys - ([File: app/models/shipit/deploy.rb])

### Summary
`Stack#build_deploy` enforces the `shipit.yml`-declared deploy variable whitelist by routing all attacker/user-supplied `env` through `filter_deploy_envs`, which calls `EnvironmentVariables.permit` and raises if any key is not in the declared variable list. [1](#0-0) [2](#0-1)  `Deploy#build_rollback`, which backs `Deploy#trigger_rollback`, performs the equivalent operation but stores `env.to_h` directly, never calling `filter_rollback_envs`/`EnvironmentVariables.permit`. [3](#0-2)  This breaks the binding: `env keys authorized by the stack's `rollback.variables`/`deploy.variables` whitelist == env keys actually merged into the spawned shell process`.

### Finding Description
The whitelist model in this engine is: a `shipit.yml` author declares a fixed set of permitted variable names for `deploy`, `rollback`, and `tasks` blocks (`deploy_variables`, `rollback_variables`, task `variables`). [4](#0-3)  Every entry point that persists a `Task`/`Deploy`/`Rollback`'s `env` column is supposed to pass through `EnvironmentVariables#permit`, which partitions the hash into allowed/disallowed keys and raises `NotPermitted` if any key isn't in the declared list. [5](#0-4)  `Stack#trigger_task` and `Stack#build_deploy` both do this correctly. [6](#0-5) 

`Deploy#build_rollback`, however, sets `env: env.to_h` with no call to `filter_rollback_envs` or `EnvironmentVariables.permit` at all:
```ruby
def build_rollback(user = nil, env: nil, force: false)
  Rollback.new(
    ...
    env: env.to_h,
    ...
  )
end
``` [7](#0-6) 

The persisted `Rollback#env` is later merged verbatim into the process environment used to spawn shell commands: `TaskCommands#env` merges `@task.env` on top of `@stack.env` and other computed values, [8](#0-7)  and `Command#unbundled_env`/`Command#start` feeds that hash straight into `PTY.spawn`. [9](#0-8)  Because `Command#interpolate_environment_variables` also substitutes `$VARNAME` tokens found in step scripts from this same `env` hash, [10](#0-9)  an attacker-supplied key that collides with a name referenced by a rollback/rescue step (or with well-known process env vars such as `PATH`, `BUNDLE_GEMFILE`, `RUBYOPT`, `GIT_SSH_COMMAND`, `LD_PRELOAD`) is not filtered out and reaches the spawned process.

This is the same bug class as the reported Aave issue: a value (env key/value) is written into a shared structure (the process environment used for all rollback steps) without validating it against the schema (declared whitelist) that governs that structure, so an out-of-schema value corrupts/overrides adjacent, trusted fields.

### Impact Explanation
Rollback steps execute the same `shipit.yml` `rollback.override`/deploy scripts on the deploy host as regular deploys. [11](#0-10)  An authenticated user who is authorized to trigger a rollback for a stack, but who the whitelist is meant to restrict to only the declared `rollback.variables`, can instead inject arbitrary environment keys (e.g. overriding `PATH`, `BUNDLE_GEMFILE`, `GIT_SSH_COMMAND`, `RUBYOPT`) into the rollback task's spawned shell process. Depending on the deploy scripts in use, this can escalate to arbitrary command execution on the deploy host (Critical - RCE on the deploy host), since these env vars directly influence what binaries/config are loaded by the shell steps run via `Command#start`. [12](#0-11) 

### Likelihood Explanation
The vulnerable code path (`Deploy#build_rollback` / `Deploy#trigger_rollback`) is reachable by any actor permitted to trigger rollbacks for a stack — the exact class of user the whitelist mechanism is designed to constrain to declared variables (as proven by the equivalent, correctly-filtered deploy path and by the dedicated `filter_rollback_envs` method that exists in `DeploySpec` but is never invoked from this model method). [13](#0-12)  No additional privilege beyond ordinary rollback-trigger permission is required, and the omission is a straightforward code-path asymmetry rather than a timing or race condition, making it reliably triggerable.

### Recommendation
Route `env` through `stack.filter_rollback_envs(env.to_h)` (or the equivalent `EnvironmentVariables.with(env).permit(rollback_variables)`) inside `Deploy#build_rollback`, mirroring `Stack#build_deploy`'s use of `filter_deploy_envs`, so that only whitelisted keys declared in `shipit.yml`'s `rollback.variables` (or the deploy-variable fallback) can ever be persisted into `Rollback#env` and subsequently spawned.

### Proof of Concept
1. Attacker has permission to trigger a rollback on a stack whose `shipit.yml` declares no `rollback.variables` (or a narrow whitelist), e.g. via any endpoint that ultimately calls `deploy.trigger_rollback(user, env: attacker_env, force: ...)`.
2. Attacker supplies `env: { "BUNDLE_GEMFILE" => "/tmp/malicious/Gemfile" }` (a key never declared in `rollback.variables`).
3. `Deploy#build_rollback` stores this unfiltered hash verbatim in `Rollback#env`:
```ruby
env: env.to_h,   # app/models/shipit/deploy.rb:97 — no whitelist check
```
4. When the rollback task runs, `TaskCommands#env` merges `@task.env` (the attacker-controlled hash) into the process environment, and `Command#start` spawns the rollback's shell steps with `BUNDLE_GEMFILE` pointed at attacker-controlled content, letting the attacker control which gems/scripts are loaded during the run — achieving code execution on the deploy host outside the constraints the whitelist was meant to enforce.

### Citations

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

**File:** lib/shipit/environment_variables.rb (L35-44)
```ruby
    def sanitize_env_vars(variable_definitions)
      allowed_variables = variable_definitions.map(&:name)

      allowed, disallowed = @env.partition { |k, _| allowed_variables.include?(k) }.map(&:to_h)

      error_message = "Variables #{disallowed.keys.to_sentence} have not been whitelisted"
      raise NotPermitted, error_message unless disallowed.empty?

      allowed
    end
```

**File:** app/models/shipit/deploy.rb (L90-117)
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

    # Rolls the stack back to this deploy
    def trigger_rollback(user = AnonymousUser.new, env: nil, force: false, lock: true)
      rollback = build_rollback(user, env:, force:)
      rollback.save!
      rollback.enqueue

      if lock
        lock_reason = "A rollback for #{rollback.since_commit.sha} has been triggered. " \
          "Please make sure the reason for the rollback has been addressed before deploying again."
        stack.update!(lock_reason:, lock_author_id: user.id)
      end

      rollback
    end
```

**File:** app/models/shipit/deploy_spec.rb (L132-149)
```ruby
    def rollback_steps
      around_steps('rollback') do
        config('rollback', 'override') { discover_rollback_steps }
      end
    end

    def rollback_steps!
      rollback_steps || cant_detect!(:rollback)
    end

    def rollback_variables
      if config('rollback', 'variables').nil?
        # For backwards compatibility, fallback to using deploy_variables if no explicit rollback variables are set
        deploy_variables
      else
        Array.wrap(config('rollback', 'variables')).map(&VariableDefinition.method(:new))
      end
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

**File:** lib/shipit/command.rb (L51-55)
```ruby
    def interpolate_environment_variables(argument)
      return argument.map { |a| interpolate_environment_variables(a) } if argument.is_a?(Array)

      EnvironmentVariables.with(env).interpolate(argument)
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
