## Title
Environment variable allow-list validated against the latest cached `shipit.yml`, but interpolated into the shipit.yml steps of the (older) commit actually deployed - ([File: app/models/shipit/stack.rb], [File: app/models/shipit/deploy_spec/file_system.rb], [File: lib/shipit/task_commands.rb])

## Summary
Analogous to the flashloan report's core defect — a security check that validates one thing while a different, unverified thing is what actually gets executed — Shipit's deploy/rollback environment-variable allow-list is validated against `Stack#cached_deploy_spec` (always derived from the **latest reachable commit**, refreshed by `CacheDeploySpecJob`), while the shell steps that actually consume those variables are read from the `shipit.yml` of the **specific commit being deployed** (`until_commit`), checked out fresh into the task's working directory. The permitted-key set and the executed-key set are bound to two different refs.

## Finding Description
`Stack#build_deploy` filters user-supplied `env` through `filter_deploy_envs`, which is delegated to `cached_deploy_spec`: [1](#0-0) [2](#0-1) 

`cached_deploy_spec` is populated by `CacheDeploySpecJob`, which always checks out the **most recently reachable commit** on the branch, not the commit that a given deploy targets: [3](#0-2) 

`EnvironmentVariables#permit` enforces the allow-list defined by `deploy_variables` (i.e. the `deploy.variables` key of whichever `shipit.yml` was last cached): [4](#0-3) [5](#0-4) [6](#0-5) 

However, when the task actually runs, `TaskCommands` builds a **new** `DeploySpec::FileSystem` rooted at `@task.working_directory` — i.e. the checkout of the commit actually being deployed (`until_commit`), not the HEAD commit whose spec was cached: [7](#0-6) [8](#0-7) 

The interpolation of `$VARNAME` tokens inside step commands (`deploy.override`, `machine.environment`, custom `tasks.*.steps`, etc.) happens via `EnvironmentVariables#interpolate`/`Command#interpolated_arguments`, using whatever value ended up in the already-filtered `env` hash: [9](#0-8) [10](#0-9) 

Because the *permitted* key set is bound to the ref represented by `cached_deploy_spec` (latest HEAD) and the *executed* steps/behavior are bound to the ref of `until_commit` (which can be any older, still-reachable commit, e.g. via rollback or an explicit `sha` deploy request), an env var that is declared (and thus allow-listed) only in the newer `shipit.yml` can be smuggled into and interpolated by an older commit's deploy/rollback/task steps that never declared or vetted that variable. If an older script blindly does something like `eval $SOME_FLAG` or conditionally runs privileged/destructive branches keyed off a variable name that later became "safe" to pass, an authorized-but-limited deployer can widen the accepted variable set beyond what the actual executing script's author intended, purely by choosing which commit to deploy/roll back to.

This is a direct structural analog of the reported bug class: a guard (`onFlashLoan`/`FLASH.ceiling()` in the external report; `permit`/`cached_deploy_spec` here) validates against one artifact while the code that is executed operates on another, unverified artifact (the flash contract's actual state vs. the deployed commit's actual `shipit.yml`).

## Impact Explanation
This does not itself grant remote code execution or credential exfiltration by an *unprivileged* actor — exploitation requires a user who already has `deploy:stack`/`lock:stack` permission (or UI access) on the target stack, i.e. it is a within-boundary escalation from "deploy any commit with the currently-allowed variables" to "deploy an older commit with variables it never declared or expected." Per the engine's own impact bar (unauthorized deploy/rollback semantics, cross-boundary execution), this is best framed as a `High` concern only insofar as it breaks the intended binding between "which `shipit.yml` approved a variable" and "which `shipit.yml`'s steps consume it" — it does not, on the evidence gathered, provide a path for a credential-less/anonymous attacker to cross an authentication or authorization boundary.

## Likelihood Explanation
Requires: (1) a stack whose `shipit.yml` `deploy.variables`/`rollback.variables`/`tasks.*.variables` list changes over time, and (2) a user with deploy/rollback permission choosing to deploy or roll back to an older commit while supplying an `env` key that is only allow-listed in the newer, cached spec. This is plausible in normal operation (rollbacks are a core supported feature), but the actual damage depends entirely on what the older commit's shell steps do with an unexpected variable — this is speculative without a concrete vulnerable `shipit.yml` step example in this codebase.

## Recommendation
Validate (and interpolate) task/deploy/rollback environment variables against the `DeploySpec` of the commit actually being executed (`until_commit`), not the stack's cached "latest HEAD" spec. If the cached spec must be used for early request-time validation (e.g. before the commit is checked out), re-validate the allow-list again once the target commit's own `shipit.yml` is available, and reject/strip any variable not declared by that specific commit's spec before interpolation.

## Proof of Concept
1. Commit A (`shipit.yml`): does not declare `deploy.variables: [DANGEROUS_FLAG]`, but its `deploy.override` step blindly does something like `./deploy.sh --flag=$DANGEROUS_FLAG` where an empty/unset value is safe and a set value changes behavior unexpectedly (e.g. skips a safety check written generically to check `$DANGEROUS_FLAG`).
2. Commit B (later, HEAD): `shipit.yml` adds `deploy.variables: [{name: DANGEROUS_FLAG}]` for legitimate reasons tied to commit B's own script logic. `CacheDeploySpecJob` recomputes `stack.cached_deploy_spec` from commit B.
3. A deployer with `deploy:stack` calls the deploy API with `sha` = commit A's sha and `env: {DANGEROUS_FLAG: "1"}`. `Stack#build_deploy` → `filter_deploy_envs` consults `cached_deploy_spec` (commit B's spec), which allow-lists `DANGEROUS_FLAG`, so it passes through into `task.env`. [1](#0-0) 
4. At execution time, `TaskCommands#deploy_spec` checks out commit A and interpolates `$DANGEROUS_FLAG` into commit A's `deploy.override` step — a value commit A's own `shipit.yml` never declared or expected to receive. [7](#0-6)

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

**File:** app/models/shipit/stack.rb (L527-531)
```ruby
    delegate :plugins, :task_definitions, :hidden_statuses, :required_statuses, :soft_failing_statuses,
             :blocking_statuses, :deploy_variables, :rollback_variables, :filter_task_envs, :filter_deploy_envs,
             :filter_rollback_envs, :maximum_commits_per_deploy, :pause_between_deploys, :retries_on_deploy,
             :retries_on_rollback,
             to: :cached_deploy_spec
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

**File:** app/models/shipit/deploy_spec.rb (L120-122)
```ruby
    def deploy_variables
      Array.wrap(config('deploy', 'variables')).map(&VariableDefinition.method(:new))
    end
```

**File:** app/models/shipit/deploy_spec.rb (L174-176)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
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

**File:** lib/shipit/task_commands.rb (L8-21)
```ruby
    def initialize(task)
      @task = task
      @stack = task.stack
    end

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

**File:** lib/shipit/command.rb (L81-83)
```ruby
    def interpolated_arguments
      interpolate_environment_variables(@args)
    end
```
