### Title
Environment-variable whitelist is checked against the stack's cached (HEAD) `shipit.yml`, but the value is injected into the shell for whatever commit is actually checked out — ([File: app/models/shipit/stack.rb])

### Summary
`Stack#build_deploy` / `Stack#trigger_task` validate a user-supplied `env` hash against `deploy_variables`/`task.variables_with_defaults`, both of which are read from `stack.cached_deploy_spec` — a snapshot of the repository's `shipit.yml` cached asynchronously from whatever commit happened to be `commits.reachable.last` at cache time [1](#0-0) . The actual shell environment used when the task runs is built later, from a fresh `DeploySpec::FileSystem` read off the *actually checked-out* commit (`@task.until_commit`, which a caller can set to any historic commit sha) [2](#0-1) [3](#0-2) , and the user's already-permitted `@task.env` is merged in **last**, overriding whatever `machine_env`/defaults that specific commit's own `shipit.yml` declares [4](#0-3) . This is the "environment key permitted vs. environment key spawned" binding: the whitelist check and the actual spawn happen against two different revisions of `shipit.yml`.

### Finding Description
- `EnvironmentVariables#permit` enforces that only variable names declared in the deploy spec can be passed through [5](#0-4) .
- The deploy spec used for that permit check is `stack.cached_deploy_spec`, populated by `CacheDeploySpecJob`, which checks out `stack.commits.reachable.last` — i.e., the branch **HEAD**, not the commit that is about to be deployed [6](#0-5) .
- `Deploy`/`Task` creation calls `filter_deploy_envs`/`definition.filter_envs`, both delegated to this cached (HEAD) spec [7](#0-6) , then stores the permitted hash as `task.env`.
- The user can pick an arbitrary `until_commit`/`sha` for the deploy (the API accepts a `sha` parameter resolved to any commit known to the stack), decoupling the commit whose `shipit.yml` was used for the whitelist check from the commit that is actually checked out and run.
- At execution time, `TaskCommands#env` builds the real process environment by merging, in order: base env, `stack.env`, fixed fields, `deploy_spec.machine_env` (loaded fresh from the **checked-out** commit's `shipit.yml`, via `DeploySpec::FileSystem.new(@task.working_directory, @stack)`), and finally `@task.env` last [4](#0-3) .
- Because `@task.env` is merged last, its keys silently override the `machine_env` values that the actually-deployed commit's own `shipit.yml` intended for those same keys, even though that commit's spec may never have declared such a variable name or intended a different default/value for it.

### Impact Explanation
This lets a stack collaborator with ordinary deploy-trigger rights (the same actor the "permitted `env`" mechanism is supposed to constrain to spec-declared names/values) supply environment overrides that are validated against a newer/HEAD `shipit.yml` but actually get spawned into the shell context of an older or different commit that never opted into (or expected) that variable. Depending on what the older commit's build/deploy steps do with machine-provided variables of the same name (e.g. a variable intended purely as an internal machine flag in the newer config could collide with an older commit's differently-scoped identically named variable), this can silently change build/deploy behavior for a specific target commit outside the bounds the target commit's own configuration authorizes — a stale-authorization/TOCTOU issue matching the "environment key permitted vs spawned" binding class called out in the assignment. It does not, on its own, demonstrate concrete RCE, credential exfiltration, or cross-repository writes with the evidence gathered here.

### Likelihood Explanation
Requires only standard, already-authorized deploy-trigger capability (no privileged Shipit role, no ApiClient token beyond what deploying already requires, no host GitHub credentials) and depends only on the attacker choosing an older `sha` together with a variable name allowed by the current/cached spec. The cache lag window (`CacheDeploySpecJob` runs asynchronously and can legitimately be behind HEAD, and users can explicitly target older commits at any time) makes the divergence easy to produce deterministically rather than requiring a race.

### Recommendation
Validate/permit the user-supplied `env` (and task `variables_with_defaults`) against the `DeploySpec` of the actual commit being deployed (`until_commit`), not the stack's separately cached HEAD spec, or re-validate at execution time immediately before merging `@task.env` into the process environment, rejecting keys not declared by the checked-out commit's own `shipit.yml`.

### Proof of Concept
Not independently verified end-to-end against a live instance; based on static code-path analysis only:
1. Attacker (ordinary deploy user) has repo write/deploy access to a stack.
2. Attacker adds `deploy.variables` entry named `FOO` to `shipit.yml` on the current branch HEAD, waits for/triggers `CacheDeploySpecJob` (or relies on existing cache).
3. Attacker requests a deploy of an **older** commit (`sha=<old_sha>`, e.g. via the API `Api::DeploysController#create`) with `env: { "FOO" => "<attacker value>" }`.
4. `Stack#build_deploy` permits `FOO` because it's declared in the *cached* (HEAD) spec (`app/models/shipit/stack.rb:161-172`), and stores it as `task.env`.
5. At execution, `checkout_repository` checks out `until_commit` = the old sha (`app/models/shipit/task_execution_strategy/default.rb:68-83`); `TaskCommands#env` loads that old commit's actual `machine_env` and then overwrites `FOO` (and any other matching key) with the attacker-supplied value (`lib/shipit/task_commands.rb:33-48`), even though the old commit's own `shipit.yml` never declared or expected `FOO`.

Given the tool-call limit, I was not able to trace a concrete downstream sink (e.g., unescaped shell interpolation of `FOO` in the old commit's deploy scripts) that would elevate this to remote code execution; that would require inspecting the specific `shipit.yml` step definitions and `EnvironmentVariables#interpolate`'s Shellwords escaping in more depth than the remaining budget allowed.

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

**File:** app/models/shipit/task_execution_strategy/default.rb (L68-83)
```ruby
      def checkout_repository
        unless @commands.fetched?(@task.until_commit).tap(&:run).success?
          # acquire_git_cache_lock can take upto 15 seconds
          # to process. Try to make sure that the job isn't
          # marked dead while we attempt to acquire the lock.
          @task.ping
          @task.acquire_git_cache_lock do
            @task.ping
            unless @commands.fetched?(@task.until_commit).tap(&:run).success?
              capture!(@commands.fetch_commit(@task.until_commit))
            end
          end
        end
        capture_all!(@commands.clone)
        capture!(@commands.checkout(@task.until_commit))
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
