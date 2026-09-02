### Title
Deploy-permitted environment variables bypass the rollback whitelist via automatic revert-on-abort - ([File: app/models/shipit/deploy.rb])

### Summary
`Shipit::Api::RollbacksController#create` enforces a rollback-specific environment whitelist (`stack.filter_rollback_envs`) before triggering a rollback. However, the automatic "rollback once aborted" path — triggered when a running deploy is aborted with `rollback_once_aborted: true` — reuses the deploy's already-stored `env` (which was only ever validated against the *deploy* variable whitelist) and forwards it directly into the rollback/revert task, never re-validating it against the *rollback* variable whitelist.

### Finding Description
The binding that should hold is: *environment key permitted for rollback == environment key that ends up in the rollback task's spawned environment*. This equality is enforced on the "manual rollback" path but not on the "abort-triggered revert" path.

- Manual rollback path (`RollbacksController#create`) filters supplied env through the rollback-specific whitelist: [1](#0-0) 

- `filter_rollback_envs` and `filter_deploy_envs` are two *distinct* whitelists (`rollback_variables` vs `deploy_variables`), meaning a shipit.yml author can intentionally permit a variable for deploys but disallow it for rollbacks: [2](#0-1) 

- When an active deploy is aborted with `rollback_once_aborted: true` (exactly what `RollbacksController#create` does when a deploy is in progress), the `Deploy` state machine invokes `trigger_revert_if_required` on transition to `aborted`: [3](#0-2) 

- `trigger_revert_if_required` passes `env:` — the deploy's *own* `env` attribute, which was only ever sanitized against `deploy_variables` at deploy-creation time — straight into `trigger_rollback`/`trigger_revert`, with no call to `filter_rollback_envs`: [4](#0-3) 

- Those same env values are later merged into the actual shell execution environment for the task's commands, including `$VAR` shell interpolation performed by `EnvironmentVariables#interpolate`: [5](#0-4) [6](#0-5) 

This exactly mirrors the report's bug class: `vote()` enforces a whitelist check that `deposit_for()`/`poke()` (a different code path reaching the same effective state change) does not — here `RollbacksController#create`'s explicit `filter_rollback_envs` call is bypassed by the `abort! → trigger_revert_if_required` path, which reuses env values that were only cleared for a different, unrelated whitelist (`deploy_variables`).

### Impact Explanation
An actor holding only `deploy:stack` permission (the normal permission required to trigger and abort deploys) can supply a value for any variable that is whitelisted in `deploy.variables` but deliberately excluded from `rollback.variables` in `shipit.yml`. By starting a deploy with that variable set, then immediately requesting a rollback while the deploy is active (which triggers `abort!(..., rollback_once_aborted: true)` instead of the whitelist-checked rollback path), the attacker forces that variable into the rollback/revert task's environment despite it never having passed `filter_rollback_envs`. Since task environment variables are interpolated into shell commands defined in `shipit.yml`'s `rollback`/`fetch`/`steps` sections, this can inject attacker-controlled values into commands executed on the deploy host — i.e., an unauthorized rollback with attacker-controlled variables, potentially escalating to command injection/RCE on the deploy host depending on how the operator's `shipit.yml` scripts consume the variable.

### Likelihood Explanation
Reachable by any actor with existing `deploy:stack` permission on the target stack, no additional credentials needed beyond what's already required to trigger deploys — likelihood is moderate-to-high wherever an operator's `shipit.yml` defines `deploy.variables` more permissively than `rollback.variables` (a supported, documented pattern).

### Recommendation
In `Deploy#trigger_revert_if_required` (and `trigger_revert`/`trigger_rollback` when invoked from the abort path), re-sanitize `env` through `stack.filter_rollback_envs(env)` before constructing the `Rollback`, exactly as `RollbacksController#create` does for the manual path, so the same permitted-vs-spawned binding holds regardless of which code path triggers the rollback.

### Proof of Concept
1. Configure `shipit.yml` with `deploy.variables` including `DANGEROUS_VAR` but `rollback.variables` excluding it, where a `rollback` step uses `$DANGEROUS_VAR`.
2. As a client with `deploy:stack` permission, `POST /api/stacks/:id/deploys` with `env: { DANGEROUS_VAR: "<payload>" }` — accepted since it's permitted for deploy variables.
3. While the deploy is running, `POST /api/stacks/:id/rollbacks` for the previous commit; since the deploy is active, `RollbacksController#create` takes the `active_task.abort!(..., rollback_once_aborted_to: deploy, rollback_once_aborted: true)` branch [7](#0-6) .
4. On abort, `trigger_revert_if_required` fires and forwards the deploy's already-set `env` (containing `DANGEROUS_VAR`) into the rollback task without ever calling `filter_rollback_envs` [4](#0-3) .
5. The rollback task executes with `DANGEROUS_VAR` set and interpolated into its shell steps, despite that variable never being permitted for rollbacks.

### Citations

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

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```

**File:** app/models/shipit/deploy.rb (L13-13)
```ruby
      after_transition to: :aborted, do: :trigger_revert_if_required
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
