Found a genuine analog: `Deploy#build_rollback` at `app/models/shipit/deploy.rb:90-102` stores `env: env.to_h` completely unfiltered, while every other env-accepting path (`Stack#build_deploy`, `Stack#trigger_task`) explicitly runs the caller-supplied env through the whitelist filter (`filter_deploy_envs` / `definition.filter_envs`) backed by `EnvironmentVariables.permit` in `lib/shipit/environment_variables.rb:13-18,35-44`, which raises `NotPermitted` for any key not declared in `shipit.yml`'s `deploy.variables`/`rollback.variables`.

### Title
Unfiltered environment variables in `Deploy#build_rollback` bypass the `shipit.yml` variable whitelist enforced everywhere else - (File: app/models/shipit/deploy.rb)

### Summary
Every other task-creation path in the engine enforces a binding: "environment key permitted by `shipit.yml`" == "environment key spawned into the deploy/rollback shell." `Stack#build_deploy` calls `filter_deploy_envs(env.to_h)` [1](#0-0)  and `Stack#trigger_task` calls `definition.filter_envs(env)` [2](#0-1) , both ultimately calling `EnvironmentVariables#permit`, which raises `EnvironmentVariables::NotPermitted` if any key isn't in the whitelist derived from `deploy_variables`/`rollback_variables` in `shipit.yml` [3](#0-2) [4](#0-3) . However, `Deploy#build_rollback` stores the caller-supplied `env` completely unfiltered: `env: env.to_h` [5](#0-4) .

### Finding Description
The equality that should hold across the codebase is: **env key accepted into a task's `env` column == env key present in the whitelist declared by that stack's `shipit.yml` (`deploy.variables` / `rollback.variables`)**. This is enforced via `filter_deploy_envs`/`filter_rollback_envs` (delegating to `DeploySpec#filter_deploy_envs`/`#filter_rollback_envs` at `app/models/shipit/deploy_spec.rb:174-180`), which both funnel through `EnvironmentVariables.with(env).permit(variable_definitions)`.

`Stack#build_deploy` respects this binding (`filter_deploy_envs(env.to_h)`). But `Deploy#build_rollback`, which is the model method backing `Deploy#trigger_rollback` (a user/API-triggered action to roll a stack back to a specific deploy), skips the filter entirely and persists `env: env.to_h` directly onto the new `Rollback` record. This `env` later gets merged into the actual shell environment used to spawn the rollback's deploy commands (via `TaskCommands#env` merging `@task.env`, `lib/shipit/task_commands.rb:33-48`, and ultimately `Command#start`/`PTY.spawn` in `lib/shipit/command.rb:85-105`).

The net effect: a rollback triggered with an env hash containing keys never declared in the stack's `rollback.variables` whitelist will still have those keys spawned into the rollback shell process, whereas the identical request path for a normal deploy (`build_deploy`) would reject it with `EnvironmentVariables::NotPermitted` (caught and rendered as a 422 by `rescue_from EnvironmentVariables::NotPermitted` in `app/controllers/shipit/api/base_controller.rb:14`).

### Impact Explanation
This breaks the "environment key permitted (by `shipit.yml`) versus environment key spawned (into the shell)" binding named in scope. An authenticated user with only `deploy:stack` permission (no special repo-write access) can trigger a rollback carrying arbitrary environment variable names/values, which are directly interpolated into shell commands via `Command#interpolate_environment_variables` and `EnvironmentVariables#interpolate` (`lib/shipit/environment_variables.rb:20-27`, using `Shellwords.escape`), and exported into the child process environment (`unbundled_env` merge, `lib/shipit/command.rb:103-105`). This allows overriding variables the `shipit.yml` author never intended to expose to end users (e.g., variables consumed by `deploy.override`/`rollback.override` scripts, or environment variables that influence command behavior), an escalation beyond what the repository owner authorized via the whitelist — a form of unauthorized influence over the executed deploy/rollback process on the deploy host.

### Likelihood Explanation
Reachable by any authenticated Shipit user/API client with standard `deploy:stack` permission triggering a rollback with a custom `env` hash — no special privilege, webhook secret, or GitHub App key is required, and no host misconfiguration is needed. The whitelist bypass is a direct, unconditional code path (`env.to_h` with no `permit` call) rather than a race condition or edge case.

### Recommendation
In `Deploy#build_rollback`, filter the incoming `env` through `stack.filter_rollback_envs(env.to_h)` (the existing method already defined and used elsewhere, `app/models/shipit/deploy_spec.rb:178-180`) before assigning it to the `Rollback` record, matching the pattern used in `Stack#build_deploy`.

### Proof of Concept
1. Configure a stack's `shipit.yml` with `rollback.variables` containing only, e.g., `SAFE_VAR`.
2. As an authenticated user/API client with `deploy:stack` permission, call `deploy.trigger_rollback(user, env: { 'UNSAFE_VAR' => 'malicious_value' })` (or the equivalent rollback API endpoint that funnels into `Deploy#build_rollback`).
3. Observe that, unlike an equivalent call to `Stack#build_deploy` with the same unwhitelisted key (which raises `EnvironmentVariables::NotPermitted`), the rollback is created successfully with `UNSAFE_VAR` stored in `env`, and it is subsequently merged into the shell environment for the rollback's `Command` execution.

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
