Found it: `Deploy#build_rollback` in `app/models/shipit/deploy.rb` bypasses the whitelist filter that every other entry point uses.

`RollbacksController#create` computes `rollback_env = stack.filter_rollback_envs(params.env)` before calling `deploy.trigger_rollback` [1](#0-0) , and `Stack#build_deploy` similarly calls `filter_deploy_envs(env.to_h)` [2](#0-1) . Both routes rely on `EnvironmentVariables#permit`, which raises `NotPermitted` for any key not declared in the stack's `shipit.yml` (`deploy.variables` / `rollback.variables`) [3](#0-2) .

However, `Deploy#trigger_revert_if_required` — invoked automatically on the `aborted` state transition (`after_transition to: :aborted, do: :trigger_revert_if_required`) [4](#0-3)  — calls `rollback_once_aborted_to.trigger_rollback(aborted_by, env:, force: true)` or `trigger_revert(force: true, env:)`, passing `env:` straight from the deploy's own **unfiltered/raw** `env` attribute [5](#0-4) . `trigger_revert` then persists this env directly onto the new `Rollback` without ever calling `filter_rollback_envs`/`EnvironmentVariables.permit`: `env: env || self.env` [6](#0-5) . Likewise `build_rollback` sets `env: env.to_h` with no filtering call at all [7](#0-6) .

At task-execution time, `TaskCommands#env` merges `@task.env` unconditionally into the spawned process environment: `.merge(@task.env)` [8](#0-7) , and `Command#unbundled_env`/`#start` spawns the actual OS process with that hash, including interpolation of `$VAR` references from `shipit.yml` step arguments via `EnvironmentVariables#interpolate` [9](#0-8) .

This reproduces the report's bug class precisely: `zap()`'s `path` argument was accepted broadly by one function (`_zap`) but only partially checked/used by the function that actually commits to the trusted action (`enter`), letting the caller smuggle extra unchecked elements into the effective action. Here, the "environment keys permitted" binding (`filter_deploy_envs`/`filter_rollback_envs` against `shipit.yml`-declared variable names) is bypassed on the automatic-rollback-on-abort code path, so the "environment keys spawned" into the deploy host's shell process are **not** the ones that were declared/permitted — they are whatever the original deploy's `env` contained.

### Title
Environment variables bypass the deploy/rollback whitelist on automatic rollback-on-abort - (File: app/models/shipit/deploy.rb)

### Summary
`Deploy#trigger_revert_if_required`, `#trigger_revert`, and `#build_rollback` propagate a task's `env` hash into a newly created `Rollback` without passing it through `EnvironmentVariables.permit` (`filter_rollback_envs`), unlike every user-facing entry point (`RollbacksController#create`, `Stack#build_deploy`, `Stack#trigger_task`). This breaks the "environment key permitted" vs. "environment key spawned" binding: whatever env values ended up on the deploy (which could include values that were valid for `deploy.variables` but are not declared in `rollback.variables`, or vice versa across shipit.yml edits) get shelled out unfiltered on the automatically triggered rollback.

### Finding Description
Every documented/controlled way to set task environment variables funnels through `EnvironmentVariables#permit`, which enforces that only variables declared in the stack's `shipit.yml` (`deploy.variables` / `rollback.variables` / task `variables`) may be forwarded to the spawned deploy script [3](#0-2) . This is enforced at:
- `RollbacksController#create` via `stack.filter_rollback_envs(params.env)` [10](#0-9) 
- `Stack#build_deploy` via `filter_deploy_envs(env.to_h)` [2](#0-1) 
- `Stack#trigger_task` via `definition.filter_envs(env)` [11](#0-10) 

But the automatic-rollback path skips this filter entirely:
- `Deploy#trigger_revert_if_required` (called on the `aborted` state transition) forwards `env:` (the aborted deploy's own, already-permitted-at-creation-time, but *for `deploy.variables`, not necessarily `rollback.variables`*) straight to `trigger_rollback`/`trigger_revert` [5](#0-4) .
- `#trigger_revert` sets `env: env || self.env` directly on the created `Rollback` record with no call to `filter_rollback_envs` [6](#0-5) .
- `#build_rollback` similarly sets `env: env.to_h` unfiltered [7](#0-6) .

Since `rollback.variables` can be configured independently of `deploy.variables` in `shipit.yml` (falling back to `deploy_variables` only when `rollback.variables` is unset) [12](#0-11) , a repo owner (who fully controls `shipit.yml` and therefore is the actor with write access to the repo, but is not necessarily the same principal who triggered the original deploy's `env`) can declare a narrower `rollback.variables` whitelist than `deploy.variables`. Any deploy env key that was legitimately permitted under `deploy.variables` but is *not* in `rollback.variables` will still reach the spawned rollback shell process, because the enforcement (`filter_rollback_envs`) is only applied on the explicit `RollbacksController` path, not on the auto-triggered-on-abort path.

### Impact Explanation
This escalates into "an environment key permitted versus an environment key spawned" as explicitly called out as an in-scope binding. It allows a task whose env was valid at deploy-time to smuggle a variable into the rollback script's process environment despite the stack's `shipit.yml` explicitly restricting which variables the rollback step is allowed to see/consume, undermining the config-declared trust boundary that `EnvironmentVariables.permit` exists to enforce. Depending on what the deploy/rollback shell scripts do with unexpected env values (e.g. reading a `SAFETY_DISABLED`-style flag that only `deploy.variables` declared, but the `rollback` steps blindly consume any env var by name), this can change rollback behavior in a way the stack owner did not sanction.

### Likelihood Explanation
Requires no special privilege beyond being able to trigger a deploy with permitted env vars and have it get aborted (or use `rollback_once_aborted`) — a normal, unprivileged Shipit deploy-permission workflow, and a `shipit.yml` where `rollback.variables` is a strict subset of `deploy.variables`. This is a fully organic path (deploy abort → automatic revert), not a hypothetical.

### Recommendation
Filter the `env` in `Deploy#trigger_revert` / `Deploy#build_rollback` / `Deploy#trigger_revert_if_required` through `stack.filter_rollback_envs` before assigning it to the `Rollback`, exactly as `RollbacksController#create` does, so the "permitted" and "spawned" environment key sets are always the same for every rollback creation path.

### Proof of Concept
1. Configure `shipit.yml` with `deploy.variables: [{name: SAFETY_DISABLED}]` and `rollback.variables: []` (or omit `SAFETY_DISABLED` from `rollback.variables`).
2. Trigger a deploy via the API with `env: {"SAFETY_DISABLED" => "1"}` — permitted by `filter_deploy_envs` for the deploy step.
3. Abort the deploy in a way that triggers `trigger_revert_if_required` (state transition to `aborted` with `rollback_once_aborted` set, or without it triggering `trigger_revert`).
4. Observe the resulting `Rollback` task's `env` still contains `SAFETY_DISABLED => "1"`, and the rollback shell process is spawned with that variable set (`TaskCommands#env` merges `@task.env` unfiltered), even though `rollback.variables` never declared/permitted it — unlike a rollback triggered explicitly through `RollbacksController#create`, which would strip it via `filter_rollback_envs`.

### Citations

**File:** app/controllers/shipit/api/rollbacks_controller.rb (L14-29)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't rollback a locked stack") if !params.force && stack.locked?
        deploy = stack.deploys.find_by(until_commit: commit) || param_error!(:sha, 'Cant find associated deploy')
        rollback_env = stack.filter_rollback_envs(params.env)

        response = nil
        if !params.force && stack.active_task?
          param_error!(:force, "Can't rollback, deploy in progress")
        elsif stack.active_task?
          active_task = stack.active_task
          active_task.abort!(aborted_by: current_user, rollback_once_aborted_to: deploy, rollback_once_aborted: true)
          response = active_task
        else
          response = deploy.trigger_rollback(current_user, env: rollback_env, force: params.force, lock: params.lock)
        end
```

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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```

**File:** app/models/shipit/deploy.rb (L13-13)
```ruby
      after_transition to: :aborted, do: :trigger_revert_if_required
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

**File:** app/models/shipit/deploy.rb (L301-310)
```ruby
    def trigger_revert_if_required
      return unless rollback_once_aborted?
      return unless supports_rollback?

      if rollback_once_aborted_to
        rollback_once_aborted_to.trigger_rollback(aborted_by, env:, force: true)
      else
        trigger_revert(force: true, env:)
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

**File:** lib/shipit/command.rb (L51-104)
```ruby
    def interpolate_environment_variables(argument)
      return argument.map { |a| interpolate_environment_variables(a) } if argument.is_a?(Array)

      EnvironmentVariables.with(env).interpolate(argument)
    end

    def success?
      !code.nil? && code.zero?
    end

    def exit_message
      "#{self} #{termination_status}"
    end

    def run
      output = []
      stream do |out|
        output << out
      end
      output.join
    end

    def run!
      output = []
      stream! do |out|
        output << out
      end
      output.join
    end

    def interpolated_arguments
      interpolate_environment_variables(@args)
    end

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
```

**File:** app/models/shipit/deploy_spec.rb (L142-149)
```ruby
    def rollback_variables
      if config('rollback', 'variables').nil?
        # For backwards compatibility, fallback to using deploy_variables if no explicit rollback variables are set
        deploy_variables
      else
        Array.wrap(config('rollback', 'variables')).map(&VariableDefinition.method(:new))
      end
    end
```
