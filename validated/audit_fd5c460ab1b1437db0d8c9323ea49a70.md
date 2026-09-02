## Title
Deploy variable whitelist is validated against the stack's cached HEAD spec while the executed steps come from the target commit's own `shipit.yml` - ("ref approved" vs "ref whose shipit.yml executes") - ([File: app/models/shipit/stack.rb], [File: lib/shipit/task_commands.rb])

### Summary
The reported bug pattern is a parameter/constant mismatch: a security-relevant check is bound to the wrong value instead of the one actually acted upon. The closest concrete analog reachable in this engine is a mismatch between the `shipit.yml` used to *authorize* a deploy's environment variables (the stack's `cached_deploy_spec`, computed from `HEAD`) and the `shipit.yml` that is actually *executed* for that deploy (the checked-out `until_commit`, which can be an older/arbitrary commit selected by the caller).

### Finding Description
When a deploy is created, `Stack#build_deploy(until_commit, user, env:, ...)` sanitizes the supplied `env` hash using `filter_deploy_envs`, which delegates to the **stack's cached spec**: [1](#0-0) 

`filter_deploy_envs`/`filter_rollback_envs` are defined on `DeploySpec` and whitelist variables using `deploy_variables`/`rollback_variables` derived from `config('deploy'...)`/`config('rollback'...)`, i.e. from whatever `shipit.yml` was cached the last time `CacheDeploySpecJob` ran against the stack's `commits.reachable.last` (effectively `HEAD`): [2](#0-1) [3](#0-2) 

However, `until_commit` — the commit that is actually going to be deployed and whose `steps` will run — can be **any deployable commit the caller chooses** (e.g. via the deploy-creation API/`sha` param), not necessarily `HEAD`. When the task executes, `TaskCommands#deploy_spec` builds a **fresh** `DeploySpec::FileSystem` from the checked-out working directory of that specific commit, not from the stack's cached spec: [4](#0-3) [5](#0-4) 

The `steps` executed by `perform` come from `@task.definition.steps` (for tasks) or, for deploys, ultimately from this on-disk spec read after checkout of `until_commit`, and the injected `env` (`@task.env`, filtered against the *HEAD* spec at creation time) is merged verbatim into the shell environment used by those steps: [6](#0-5) 

So the equality that should hold is:
`shipit.yml commit used to compute the env whitelist (HEAD via cached_deploy_spec)` == `shipit.yml commit whose steps consume that env (until_commit)`.

If an attacker (or an integrator with normal deploy-trigger rights but no push access) can influence `until_commit` to point at an older commit whose `shipit.yml` declares a different, broader set of `deploy`/`rollback` variables (or none at all, causing `EnvironmentVariables::NotPermitted` to reject variables that *should* have been allowed by that commit's own spec, or conversely, permits variables that commit's steps interpret dangerously, e.g. via `interpolate`/`Shellwords.escape` argument substitution in `Command`), the enforced whitelist and the executed spec diverge. This is structurally identical to the reported bug: the check is anchored to a value (`HEAD`'s cached spec / hardcoded `1`) that does not match the value actually operated on (`until_commit`'s own spec / the real `records` count).

### Impact Explanation
This does not itself grant unauthenticated access or bypass GitHub authentication — the attacker still needs authorization to trigger a deploy — so it doesn't cleanly reach the "Critical/High" bar defined by the rules (RCE, auth bypass, `GITHUB_TOKEN`/`github_access_token` exfiltration, cross-repo writes, or unauthorized deploy/rollback/merge). At best it could let an authorized-but-untrusted deployer smuggle environment variables that a stale/older `shipit.yml` doesn't intend to permit into that commit's deploy steps, which only matters if that commit's steps interpolate arbitrary env into shell commands. I could not fully verify, in the time available, whether any `shipit.yml`-defined step interpolates env in a way that turns an unexpected whitelist entry into command injection versus additional cross-repo write/RCE — this requires deeper reading of `lib/shipit/command.rb`'s `interpolate_environment_variables` and real-world `shipit.yml` step definitions than I was able to complete.

### Likelihood Explanation
Requires an actor who already has permission to trigger deploys (not a fully unprivileged party), and requires the target stack to have multiple historical commits with differing `deploy`/`rollback` variable declarations in their `shipit.yml`. This is a plausible but narrow condition, and it depends on host/repo configuration (differing `shipit.yml` across commits), which pushes it toward the "config-dependent" exclusion called out in the rules.

### Recommendation
If pursued, the fix would be to compute the environment whitelist from the `shipit.yml` of the specific `until_commit` being deployed (or refuse env overrides when the target commit's spec differs from the cached HEAD spec), rather than always using the stack's `cached_deploy_spec`.

### Proof of Concept
Not verified end-to-end. A conceptual PoC would be: (1) commit A on `main` with `shipit.yml` declaring `deploy.variables: [SAFE_VAR]`; CacheDeploySpecJob caches this spec. (2) Push commit B with a stricter/absent `deploy.variables`. (3) Trigger a deploy against `until_commit = A` (still `reachable`) while the stack's `cached_deploy_spec` reflects B (or vice versa) — the env filtering will succeed/fail based on B's declared variables even though A's steps and A's own spec is what actually runs. I did not execute this against the running application, and the "Reject analogs that depend on the host application not mounting the engine as documented" / config-dependent exclusions in the rules mean this may fall outside what should be counted as a qualifying finding. [7](#0-6)

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

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```

**File:** app/jobs/shipit/cache_deploy_spec_job.rb (L16-23)
```ruby
    def perform(stack)
      return if stack.inaccessible?

      commit = stack.commits.reachable.last
      commands = Commands.for(stack)
      commands.with_temporary_working_directory(commit:, recursive: false) do |path|
        stack.update!(cached_deploy_spec: DeploySpec::FileSystem.new(path, stack))
      end
```

**File:** lib/shipit/task_commands.rb (L13-31)
```ruby
    def deploy_spec
      @deploy_spec ||= DeploySpec::FileSystem.new(@task.working_directory, @stack)
    end

    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def steps
      @task.definition.steps
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

**File:** lib/shipit/task_commands.rb (L50-59)
```ruby
    def checkout(commit)
      git(
        '-c',
        'advice.detachedHead=false',
        'checkout',
        '--quiet',
        commit.sha,
        chdir: @task.working_directory
      )
    end
```
