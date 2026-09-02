Based on my investigation, I found a concrete instance of the same bug class as the external report: **a value used to select/derive a trust decision is not the same value that is subsequently trusted for the privileged action** — here, `trigger_revert` builds and enqueues a `Rollback` using a raw, unfiltered environment hash instead of applying the same `EnvironmentVariables.permit` whitelist binding that every other deploy/rollback/task entry point enforces.

### Title
Unwhitelisted environment variables can be injected into task execution via `Deploy#trigger_revert` - (File: `app/models/shipit/deploy.rb`)

### Summary
Every user-facing path that lets a caller supply an `env` hash for a `Deploy`, `Rollback`, or `Task` is required to pass through `EnvironmentVariables.permit`, which enforces the whitelist declared by `deploy.variables` / `rollback.variables` / `tasks.<id>.variables` in the repository's `shipit.yml`. `Deploy#trigger_revert`, however, builds its `Rollback` directly with the caller-supplied `env` argument, with no call to `stack.filter_rollback_envs` or any other `EnvironmentVariables.permit` gate.

### Finding Description
The binding that should hold everywhere in this engine is: **environment key permitted by `shipit.yml` (via `EnvironmentVariables.permit(variable_definitions)`) == environment key that is actually exported into the executed shell task.**

Every legitimate entry point enforces this:
- `RollbacksController#create` calls `stack.filter_rollback_envs(params.env)` before calling `trigger_rollback` [1](#0-0) 
- `Stack#build_deploy` calls `filter_deploy_envs(env.to_h)` [2](#0-1) 
- `Stack#trigger_task` calls `definition.filter_envs(env)` [3](#0-2) 
- The filter itself raises `EnvironmentVariables::NotPermitted` for any key not declared in the whitelist [4](#0-3) [5](#0-4) , and this exception is turned into a 422 by the API base controller: [6](#0-5) 

`Deploy#trigger_revert`, by contrast, assigns `env: env || self.env` directly to the created `Rollback` with **no filtering call at all**: [7](#0-6) 

That `env` hash is later merged verbatim into the shell environment used to run the deploy/rollback scripts, alongside `Shipit`'s own reserved keys, by `TaskCommands#env`: [8](#0-7) 

If any controller or job path reaches `trigger_revert` with a caller-influenced `env:` keyword (a `write:stack`/`deploy:stack` scoped `ApiClient` is enough — no repository write access or GitHub credentials are required beyond the already-issued Shipit API token), the environment-permitted-vs-environment-spawned equality is broken: an attacker-chosen key/value that was never declared in `rollback.variables` (or `deploy.variables`) in the target repository's `shipit.yml` is exported into the shell that runs the rollback's `deploy`/`rollback` steps.

### Impact Explanation
Because `shipit.yml`'s `deploy`/`rollback`/`fetch` steps are ordinary shell command sequences run on the deploy host (see `README.md` script parameters and `DeploySpec` step discovery), and those steps frequently interpolate `$VARIABLE` references via `TaskCommands`/`Command#interpolate` [9](#0-8) , an unwhitelisted environment variable injected this way can alter script behavior on the deploy host in ways the repository owner explicitly did not authorize via their whitelist. This crosses the "environment key permitted vs environment key spawned" boundary called out in scope, and can lead to unauthorized command behavior during a rollback (an unauthorized/altered "deploy" action) on infrastructure the calling `ApiClient` was only scoped to (`deploy:stack`), not to arbitrary command-level control.

### Likelihood Explanation
Likelihood is Low-to-Medium: it requires a caller who already holds an `ApiClient` token scoped `deploy:stack` for the target stack (already a privileged, if lower-tier, credential relative to full repo/GitHub access), and requires a code path that reaches `trigger_revert(env: ...)` with attacker-influenced input. I was not able to confirm from the indexed files whether any current controller/route passes a caller-supplied `env` into `trigger_revert` (unlike `trigger_rollback`, which is clearly wired to attacker input via `RollbacksController#create`). This is a real gap in the codebase's defense-in-depth (the same unconditional filtering discipline applied everywhere else is absent here), but I could not verify a currently-reachable HTTP entry point that calls `trigger_revert` with a non-empty, caller-controlled `env`.

### Recommendation
Apply the same whitelist enforcement in `Deploy#trigger_revert` that is used everywhere else:
```ruby
env: stack.filter_rollback_envs(env || self.env),
```
or otherwise ensure any `env` passed into `trigger_revert` is always run through `EnvironmentVariables.permit` against `rollback_variables` before being persisted onto the `Rollback` record, closing the gap between "environment key permitted by `shipit.yml`" and "environment key spawned in the task's shell process."

### Proof of Concept
Not concretely demonstrable from the indexed engine code alone: I could not find a currently wired controller/job that invokes `Deploy#trigger_revert` with an attacker-supplied `env:` value (the only indexed call sites pass no `env` or `self.env`). Because of index size limits, some files (e.g., additional jobs/controllers that might call `trigger_revert`) may not be fully covered — a Devin session with full repository access would be needed to confirm whether `trigger_revert`'s `env:` parameter is reachable from user input today. The missing-filter defect in `app/models/shipit/deploy.rb` lines 120-139 is nonetheless a concrete deviation from the codebase's own established environment-variable-whitelisting invariant.

### Citations

**File:** app/controllers/shipit/api/rollbacks_controller.rb (L15-28)
```ruby
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

**File:** app/controllers/shipit/api/base_controller.rb (L13-16)
```ruby
      rescue_from ApiClient::InsufficientPermission, with: :insufficient_permission
      rescue_from EnvironmentVariables::NotPermitted, with: :validation_error
      rescue_from TaskDefinition::NotFound, with: :not_found
      rescue_from Task::ConcurrentTaskRunning, with: :conflict
```

**File:** app/models/shipit/deploy.rb (L120-139)
```ruby
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
