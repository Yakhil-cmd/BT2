Confirmed analog found: the environment-variable whitelist used to validate a deploy's `env` params is derived from `stack.cached_deploy_spec` — computed from the stack's HEAD commit — while the `deploy.variables`/`deploy.override` steps that actually consume that `env` at runtime are re-read from the `shipit.yml` checked out at `until_commit` (the arbitrary, attacker-chosen SHA passed to `Api::DeploysController#create`). These two `shipit.yml` revisions are not guaranteed to be identical.

### Title
Deploy environment variables are whitelist-checked against HEAD's `shipit.yml` but executed against the `shipit.yml` of an arbitrary, older deployed commit - (File: `app/models/shipit/stack.rb`, `app/controllers/shipit/api/deploys_controller.rb`, `lib/shipit/task_commands.rb`)

### Summary
`Api::DeploysController#create` lets an authenticated `deploy:stack` client pick **any** reachable commit SHA to deploy (`stack.commits.by_sha(params.sha)`), not just HEAD. The submitted `env` hash is validated with `stack.filter_deploy_envs(env)`, which delegates to `stack.cached_deploy_spec` — a `DeploySpec` cached from the stack's **current HEAD** commit [1](#0-0) . But when the deploy actually runs, `TaskCommands#deploy_spec` re-reads `shipit.yml` from the checked-out working directory of `@task.working_directory`, i.e. from the commit actually being deployed (`until_commit`), not HEAD [2](#0-1) . The deploy's shell steps (`deploy.override`) and variable interpolation (`EnvironmentVariables#interpolate`) are driven by that older `shipit.yml`, not the one whose `deploy.variables` whitelist was actually enforced.

### Finding Description
The binding that should hold is:
```
shipit.yml revision whose deploy.variables whitelist authorized env == shipit.yml revision whose deploy steps consume env
```
This binding is broken:

1. `Api::DeploysController#create` accepts an arbitrary `sha` param for any commit already synced onto the stack and calls `stack.trigger_deploy(commit, current_user, env: params.env, ...)` [3](#0-2) .
2. `Stack#build_deploy` filters the submitted `env` using `filter_deploy_envs(env.to_h)`, which is delegated straight through to `cached_deploy_spec` [1](#0-0) [4](#0-3) .
3. `cached_deploy_spec` is computed and stored by `CacheDeploySpecJob`, always from `stack.commits.reachable.last` — the branch **HEAD**, refreshed after every sync [5](#0-4) .
4. When the `Deploy` task actually runs, `TaskCommands#deploy_spec` builds a **fresh** `DeploySpec::FileSystem` from `@task.working_directory`, which is checked out at the commit that is being deployed (i.e., `until_commit`, the caller-supplied, possibly old, `sha`) [2](#0-1) , and `DeployCommands#steps` calls `deploy_spec.deploy_steps!` against that on-disk (checked-out) config [6](#0-5) .
5. `EnvironmentVariables#interpolate` substitutes raw shell arguments with values from `@env` without additional sanitization beyond `Shellwords.escape` [7](#0-6) , and the actually-executed `deploy.override` commands come from the old commit's `shipit.yml`.

Consequently, the security decision ("is this variable name allowed, and is this its declared shape/default") is made against one `shipit.yml` (HEAD), while the code path that actually interpolates the variable into a shell command is defined by a **different** `shipit.yml` (the deployed commit's). If the repository owner ever removes or renames a deploy variable, or changes how a variable is consumed (e.g., interpolated unsafely, embedded in a URL, or fed to a task with different `select`/`default` semantics) between an old commit and HEAD, a caller holding a `deploy:stack` token can deploy the old commit while supplying env values that were only validated against the newer, unrelated whitelist.

### Impact Explanation
An attacker who already holds a `deploy:stack`-scoped `ApiClient` token (a normal, low-privilege capability meant only to trigger deploys of legitimate reachable commits with pre-approved variable names) can leverage this staleness to make an old, already-reachable commit execute deploy steps with environment variable names/values that were never vetted against that commit's own `shipit.yml`. Depending on what the older `shipit.yml`'s `deploy.override` did with that variable (unsanitized shell interpolation, a since-removed "SAFETY_DISABLED"-style toggle, etc.), this can escalate into unintended shell command execution on the deploy host — i.e., a path toward RCE on the deploy host, which the report's rubric ranks Critical. Because the confidence of exploitability depends on the exact historical `shipit.yml` content of the repo (which this analysis cannot fully audit across all possible histories), this should be treated as at least a High-severity design flaw with potential Critical impact under a concrete history.

### Likelihood Explanation
Any caller with an already-issued `deploy:stack` `ApiClient` (a token these engine deployments regularly hand out to CI/CD callers) can trigger this by simply choosing an old `sha` and any environment values whitelisted by the current HEAD's `shipit.yml`. No additional privilege escalation, session, or GitHub write access is required beyond the existing `deploy:stack` permission — the flaw is purely in the mismatch between validation-time and execution-time `shipit.yml`, which is a normal, repeatable condition (repositories evolve their `shipit.yml` over time, and Shipit explicitly supports deploying non-HEAD commits).

### Recommendation
Validate the submitted `env` against the `DeploySpec` of the commit that is actually going to be deployed (`until_commit`), not the stack's cached HEAD spec. Concretely, `Stack#build_deploy`/`#filter_deploy_envs` should build (or look up) the `DeploySpec` for `until_commit` and use that instance's `deploy_variables` to permit the incoming `env`, so the whitelist enforced always matches the `shipit.yml` version whose steps will actually execute.

### Proof of Concept
1. At commit `A` (older, still reachable on the stack), `shipit.yml` declares no `deploy.variables` whitelist entry for `DANGEROUS_VAR`, but its `deploy.override` step directly interpolates `$DANGEROUS_VAR` into a shell command without safe quoting semantics beyond `Shellwords.escape` (e.g. used to build a URL/host argument consumed by a downstream script).
2. Repository owner later updates `shipit.yml` at HEAD (commit `B`) to add `DANGEROUS_VAR` to `deploy.variables` for an unrelated, legitimate feature, and `CacheDeploySpecJob` recomputes `stack.cached_deploy_spec` from commit `B` [5](#0-4) .
3. Attacker holding a `deploy:stack` `ApiClient` token calls `POST /api/stacks/:id/deploys` with `sha: A` (commit `A`'s sha, still `stack.commits.by_sha`-reachable) and `env: { "DANGEROUS_VAR" => "<payload>" }`.
4. `Api::DeploysController#create` looks up commit `A` and calls `stack.trigger_deploy(commit_A, ...)` [3](#0-2) ; `filter_deploy_envs` permits `DANGEROUS_VAR` because it checks the **HEAD (`B`)** `cached_deploy_spec`'s whitelist, not commit `A`'s [1](#0-0) .
5. When the task runs, `TaskCommands#deploy_spec` is rebuilt from the checked-out commit `A` [2](#0-1) , and `DeployCommands#steps` executes commit `A`'s `deploy.override`, which interpolates the attacker-controlled `DANGEROUS_VAR` value that was never vetted by commit `A`'s own whitelist/semantics.

Note: full confirmation that a concrete injection primitive exists requires inspecting the actual historical `shipit.yml` content across a target deployment's commit history, which is outside what this codebase's shared engine code can prove in isolation; the structural mismatch itself (validation-time spec ≠ execution-time spec) is proven directly from the code cited above.

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

**File:** lib/shipit/task_commands.rb (L13-20)
```ruby
    def deploy_spec
      @deploy_spec ||= DeploySpec::FileSystem.new(@task.working_directory, @stack)
    end

    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-27)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?

        allow_concurrency = params.allow_concurrency.nil? ? params.force : params.allow_concurrency
        deploy = stack.trigger_deploy(commit, current_user, env: params.env, force: params.force,
                                                            allow_concurrency:)
        render_resource(deploy, status: :accepted)
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

**File:** lib/shipit/deploy_commands.rb (L1-8)
```ruby
# frozen_string_literal: true

module Shipit
  class DeployCommands < TaskCommands
    def steps
      deploy_spec.deploy_steps!
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
