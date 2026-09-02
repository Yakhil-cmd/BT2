### Title
Deploy environment variables are whitelisted against the stack's cached `shipit.yml` spec, not the spec of the commit actually being deployed - (File: `app/controllers/shipit/deploys_controller.rb`, `app/models/shipit/stack.rb`, `lib/shipit/task_commands.rb`)

### Summary
`DeploysController#deploy_params` and `Stack#build_deploy` validate user-supplied `env` values against `@stack.deploy_variables`, which is delegated to `cached_deploy_spec` - a snapshot of `shipit.yml` taken from the *current branch HEAD* and refreshed asynchronously by `CacheDeploySpecJob`. The value actually spawned at execution time, however, is taken from the fresh `DeploySpec::FileSystem` loaded from the working directory checked out to the specific commit being deployed (`until_commit`), inside `TaskCommands#deploy_spec` / `#env`. Because Shipit allows deploying *any* known historical commit by SHA (not just HEAD), the "variable name" binding checked at request time (cached HEAD spec) can diverge from the binding that governs how that value is actually interpolated into shell steps at execution time (the deployed commit's own spec). This mirrors the reported "epoch revenue" class of bug: a value is authorized against one state snapshot but consumed against a different, inconsistent one.

### Finding Description
- Web deploy creation whitelists variables using the *stack's cached spec*, not the target commit's spec: [1](#0-0) 

- The API path funnels through the same `Stack#build_deploy`, which also filters against the stack's (cached) spec via `filter_deploy_envs`: [2](#0-1) [3](#0-2) 

- `cached_deploy_spec` is a serialized column on `Stack`, refreshed out-of-band by `CacheDeploySpecJob`, always from the branch's *latest reachable* commit - not from the commit being deployed: [4](#0-3) 

- At execution time, the actual deploy steps and variable interpolation are computed by re-reading `shipit.yml` from the working directory checked out to `@task.until_commit` - i.e., a potentially different, older commit than the one whose spec was used for the whitelist check: [5](#0-4) [6](#0-5) 

- The already-filtered `task.env`/`deploy.env` value (validated against the cached/HEAD spec) is merged unconditionally into the runtime environment and substituted into the checked-out commit's own step text via `EnvironmentVariables#interpolate`: [7](#0-6) [8](#0-7) 

The equality that should hold is: `{variable names permitted at request time} == {variable names/semantics defined by shipit.yml of the exact commit that is executed}`. Because the permit check uses the stack's cached spec (tracking HEAD) while execution uses the spec of `until_commit` (any historical commit reachable by SHA), these two sets can diverge whenever a variable's definition/usage changes between commits, or whenever `cached_deploy_spec` lags behind HEAD (it is refreshed asynchronously, with an explicit re-enqueue path for exactly this staleness scenario): [9](#0-8) 

### Impact Explanation
A user who legitimately holds only `deploy:stack` permission (an ordinary contributor, not someone with `write:stack` or repository push access) can pick an arbitrary historical, already-indexed commit SHA to deploy. If an older commit's `shipit.yml` used a variable name in a way that is unsafe (e.g., directly interpolated into a step without today's stricter definition/defaults), but that variable name still passes the whitelist derived from the stack's *cached* (HEAD-tracking) spec, the attacker's value is accepted, stored on the `Task`/`Deploy` record, and then interpolated into the old commit's actual (unreviewed-for-current-state) step at execution time. This breaks the trust binding between "what was authorized as safe input" and "what code path that input actually reaches," and can lead to unintended commands running on the deploy host with attacker-controlled parameters - within the `deploy:stack` action itself, without needing repository write access or elevated Shipit permissions.

### Likelihood Explanation
Exploitation only requires: (1) `deploy:stack` permission (the baseline permission for triggering deploys, held by ordinary contributors and CI clients), (2) knowledge of an older commit SHA in the stack's history whose `shipit.yml` differs from HEAD's cached spec, and (3) the deliberate or incidental staleness of `cached_deploy_spec` (explicitly acknowledged as a real, recurring condition in `CacheDeploySpecJob`, which re-enqueues itself specifically because the head can move during/after the job runs). No signature bypass, session forgery, or GitHub-side action is needed - it is purely a mismatch between two independently-computed `DeploySpec` snapshots within the engine.

### Recommendation
Validate and filter deploy/task environment variables against the `DeploySpec` of the exact commit being deployed (`until_commit`), not the stack's cached/HEAD spec. This requires resolving the target commit's spec (e.g., via a working-directory checkout or a per-commit cached spec) before permitting/filtering `env`, and re-validating the filtered `env` again immediately before it's merged into `TaskCommands#env` at execution time, so the whitelist used for authorization is always sourced from the same `shipit.yml` revision that will actually consume the values.

### Proof of Concept
Conceptual PoC (illustrates the code-level mismatch; not a full exploit due to lack of a live deploy host):
1. At commit `A` (older, reachable in the stack's `commits` table), `shipit.yml` defines `deploy.variables: [{name: LEGACY_FLAG}]` and a step `./deploy.sh $LEGACY_FLAG`.
2. HEAD is now commit `B`, whose `shipit.yml` no longer declares `LEGACY_FLAG` for a good reason (e.g., it was found to be dangerous when interpolated raw into `deploy.sh`), but `Stack#cached_deploy_spec` has not yet been refreshed to reflect the removal (`CacheDeploySpecJob` runs asynchronously against the branch's latest reachable commit).
3. A user with only `deploy:stack` permission calls `POST /stacks/:id/deploys` (or the API equivalent) with `sha: A` and `env: { LEGACY_FLAG: "; malicious-payload" }`.
4. `DeploysController#deploy_params` / `Stack#filter_deploy_envs` permit `LEGACY_FLAG` because `@stack.deploy_variables` still reflects the stale cached spec that included it.
5. The task checks out commit `A`, `TaskCommands#deploy_spec` re-reads `A`'s `shipit.yml`, and `./deploy.sh $LEGACY_FLAG` is executed with the attacker-supplied value - all validated by a spec (`B`'s intended, stricter state) different from the one that is actually executed (`A`'s stale, permissive state). [10](#0-9) [11](#0-10)

### Citations

**File:** app/controllers/shipit/deploys_controller.rb (L25-35)
```ruby
    def create
      @deploy = @stack.trigger_deploy(
        @until_commit,
        current_user,
        env: deploy_params[:env],
        force: params[:force].present?
      )
      respond_with(@deploy.stack, @deploy)
    rescue Task::ConcurrentTaskRunning
      redirect_to(new_stack_deploy_path(@stack, sha: @until_commit.sha))
    end
```

**File:** app/controllers/shipit/deploys_controller.rb (L66-68)
```ruby
    def deploy_params
      @deploy_params ||= params.require(:deploy).permit(:until_commit_id, env: @stack.deploy_variables.map(&:name))
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

**File:** app/models/shipit/deploy_spec.rb (L174-176)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
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

**File:** app/jobs/shipit/cache_deploy_spec_job.rb (L24-28)
```ruby

      # A duplicate enqueued while this job held the dedupe lock was dropped;
      # if the head moved under us, that dropped job's work is still
      # outstanding, so hand it off rather than leaving the spec stale.
      CacheDeploySpecJob.perform_later(stack) if stack.commits.reachable.last&.id != commit&.id
```

**File:** lib/shipit/task_commands.rb (L13-21)
```ruby
    def deploy_spec
      @deploy_spec ||= DeploySpec::FileSystem.new(@task.working_directory, @stack)
    end

    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
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
