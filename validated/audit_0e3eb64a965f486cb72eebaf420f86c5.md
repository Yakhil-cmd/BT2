### Title
Rollback-on-abort reuses the deploy's unfiltered env, bypassing the `rollback.variables` whitelist - (File: `app/models/shipit/deploy.rb`)

### Summary
`Shipit::Deploy#trigger_revert_if_required` automatically re-uses the *deploy's own* `env` attribute when triggering a rollback after an aborted deploy, without re-validating it against the stack's `rollback_variables` whitelist. Every externally reachable rollback entry point (API and web) explicitly filters user-supplied `env` through `filter_rollback_envs`/`rollback_variables` before letting it reach task execution, but this internal auto-rollback path skips that filter entirely, breaking the binding between "environment key permitted for a deploy" and "environment key that ends up spawned in the rollback task's process".

### Finding Description
Two whitelists are deliberately maintained by `DeploySpec`: `deploy_variables` (via `filter_deploy_envs`) and `rollback_variables` (via `filter_rollback_envs`), which can legitimately differ (the README documents `rollback.variables` config, and `deploy_spec.rb` falls back to `deploy_variables` only if `rollback.variables` is not explicitly configured): [1](#0-0) 

Every attacker-reachable rollback trigger path enforces this second whitelist before calling `trigger_rollback`:
- API: `stack.filter_rollback_envs(params.env)` [2](#0-1) 
- Web: strong params permit only `@stack.rollback_variables.map(&:name)` [3](#0-2) 

However, `Deploy#trigger_revert_if_required`, invoked automatically `after_transition to: :aborted`, calls `trigger_rollback`/`trigger_revert` using `env:` — which is simply `self.env`, the deploy's own environment that was validated only against `filter_deploy_envs` (deploy_variables) at deploy-creation time: [4](#0-3) [5](#0-4) 

`trigger_rollback` and `trigger_revert` accept this env with no additional filtering and persist it directly on the `Rollback` record: [6](#0-5) 

That env hash is later merged verbatim into the rollback task's spawned process environment and made available for `$VAR` shell interpolation in rollback steps: [7](#0-6) [8](#0-7) [9](#0-8) 

**Binding broken:** environment key *permitted* (validated against `deploy_variables` at deploy time) ≠ environment key *spawned* (injected into the rollback task's process/interpolation context, which the stack owner scoped down via a distinct `rollback_variables` whitelist specifically to prevent it).

### Impact Explanation
An actor holding only the `deploy:stack` permission on a single stack (no repository write access, no privileged team membership) can trigger a deploy with a variable that is declared in `deploy.variables` but intentionally excluded from `rollback.variables`. If that deploy is later aborted with `rollback_once_aborted: true` (a legitimate, unprivileged flow exposed by `POST /rollbacks` when a deploy is active), the auto-triggered rollback silently carries the attacker-chosen deploy-scoped value into the rollback task's execution environment, bypassing the safety boundary the stack maintainer configured via `rollback.variables`. Because this value also flows through `EnvironmentVariables#interpolate` for `$VAR` substitution inside rollback step arguments, it can influence what rollback commands actually execute on the deploy host, defeating the intended segregation between deploy-time and rollback-time inputs.

### Likelihood Explanation
Reachable by any API client/user with only `deploy:stack` permission scoped to the target stack — no elevated `Shipit.github_teams` membership, GitHub App key, or repository write access is required. It requires the stack to define different `deploy.variables` and `rollback.variables` (a supported, documented configuration), and for the attacker to cause/trigger an abort-with-rollback of their own deploy, both of which are ordinary, unprivileged operations.

### Recommendation
In `Deploy#trigger_revert_if_required` (and any other internal call site that forwards a previously-validated `env` into a rollback), re-filter the env through `stack.filter_rollback_envs`/`rollback_variables` before passing it to `trigger_rollback`/`trigger_revert`, exactly as the API and web controllers already do for externally supplied env. Alternatively, make `trigger_rollback`/`build_rollback`/`trigger_revert` themselves always call `filter_rollback_envs` internally so no caller can bypass the whitelist.

### Proof of Concept
1. Configure a stack's `shipit.yml` with `deploy.variables: [{name: DEPLOY_ONLY_VAR}]` and `rollback.variables: []` (rollback intentionally excludes it).
2. As an API client scoped to the stack with only `deploy:stack` permission, `POST /stacks/:id/deploys` with `env: {DEPLOY_ONLY_VAR: "payload"}` — accepted because it's permitted for deploy via `filter_deploy_envs`.
3. While that deploy is active, `POST /stacks/:id/rollbacks` with `rollback_once_aborted_to` pointing at a previous successful deploy; this calls `active_task.abort!(rollback_once_aborted_to:, rollback_once_aborted: true)`.
4. When the deploy transitions to `aborted`, `trigger_revert_if_required` fires and calls `trigger_rollback(aborted_by, env: self.env, force: true)` using the original `{DEPLOY_ONLY_VAR: "payload"}` — never checked against the empty `rollback_variables` whitelist.
5. Inspect the resulting `Rollback#env` / the spawned rollback `Task`'s process environment: `DEPLOY_ONLY_VAR` is present and interpolatable in rollback steps, despite `rollback.variables` explicitly forbidding it.

### Citations

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```

**File:** app/controllers/shipit/api/rollbacks_controller.rb (L14-28)
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
```

**File:** app/controllers/shipit/rollbacks_controller.rb (L8-31)
```ruby
    def create
      @rollback = @deploy.trigger_rollback(
        current_user,
        env: rollback_params[:env]&.to_unsafe_hash,
        force: params[:force].present?
      )
      redirect_to(stack_deploy_path(@stack, @rollback))
    rescue Task::ConcurrentTaskRunning
      redirect_to(rollback_stack_deploy_path(@stack, @deploy))
    end

    private

    def load_stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end

    def load_deploy
      @deploy = @stack.deploys.find(rollback_params[:parent_id])
    end

    def rollback_params
      params.require(:rollback).permit(:parent_id, env: @stack.rollback_variables.map(&:name))
    end
```

**File:** app/models/shipit/deploy.rb (L9-17)
```ruby
    state_machine :status do
      after_transition to: :success, do: :schedule_continuous_delivery
      after_transition to: :success, do: :schedule_merges
      after_transition to: :success, do: :update_undeployed_commits_count
      after_transition to: :aborted, do: :trigger_revert_if_required
      after_transition any => any, do: :update_release_status
      after_transition any => any, do: :update_commit_deployments
      after_transition any => any, do: :update_last_deploy_time
    end
```

**File:** app/models/shipit/deploy.rb (L90-139)
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

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
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
