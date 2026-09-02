### Title
`EnvironmentVariables#interpolate` falls back to the host process's raw `ENV` for any `$VAR` not present in the task's whitelisted env - (File: `lib/shipit/environment_variables.rb`)

### Summary
`EnvironmentVariables#interpolate` resolves `$VAR` references in command strings against the task/deploy's filtered env, but silently falls back to the Shipit server process's own `ENV[variable]` when the variable is absent from that filtered hash. Because task `steps` come verbatim from the repository's `shipit.yml` (an attacker-influenced, cached artifact), any step referencing a variable that was never declared in the task's `variables:` whitelist bypasses `EnvironmentVariables#permit` entirely and captures whatever value that name has in the Shipit host's own process environment (e.g. `GITHUB_TOKEN`, `GIT_ASKPASS`) directly into the command's stdout, which is stored and rendered as task output.

### Finding Description
Broken binding: `bytes handed to the shell for "$GITHUB_TOKEN"` == `Shipit host process ENV['GITHUB_TOKEN']`, when it should equal only a value present in the operator-approved, whitelisted task env (`definition.filter_envs(env)`), or nothing at all.

Code path:
- `Stack#trigger_task` builds the task's env via `definition.filter_envs(env)`, which calls `EnvironmentVariables#permit`, raising `NotPermitted` for any *provided* variable not in the task's declared `variables:` list [1](#0-0) . This whitelist only rejects variables the caller *supplies*; it does nothing to prevent a command step from *referencing* an undeclared variable name.
- Task steps are taken straight from the cached `TaskDefinition#steps`, which is populated from `shipit.yml`'s `tasks.<id>.steps` [2](#0-1) , and turned into `Command` objects with `env:` set to the filtered task env [3](#0-2) .
- `Command#interpolate_environment_variables` wraps that filtered env in `EnvironmentVariables.with(env)` and calls `#interpolate` on each argument before spawning the process [4](#0-3) .
- `EnvironmentVariables#interpolate` performs `@env.fetch(variable) { ENV[variable] }` — i.e., if the variable is not a key of the whitelisted/filtered hash, it falls back to the **Shipit server process's own `ENV`**, not the deploy/task env, then shell-escapes and substitutes that value into the command line [5](#0-4) .
- The resulting interpolated command string is passed to `PTY.spawn`, and its output is streamed and persisted as the task's log/output [6](#0-5) , visible to any user who can view that stack's task/deploy output.
- `lib/shipit/commands.rb` and `lib/snippets/git-askpass` reference `GIT_ASKPASS`, indicating the Shipit host process is expected to carry Git credential material (e.g. a token) in its own `ENV` for git operations — confirming the stated precondition that `GITHUB_TOKEN`/`GIT_ASKPASS` exist in the host process's environment.

Attacker flow: an unprivileged contributor who controls a `shipit.yml` that eventually becomes a stack's `cached_deploy_spec` (via `CacheDeploySpecJob`, which checks out the stack's tracked branch head and rebuilds `DeploySpec::FileSystem` [7](#0-6) ) defines a task step `echo $GITHUB_TOKEN` without declaring `GITHUB_TOKEN` in that task's `variables:`. When any authorized user (or automated trigger) runs that task, the interpolation fallback substitutes the host's real `GITHUB_TOKEN` into the shell command, and the token appears verbatim in the task's captured output.

Existing guards that do not stop this: `EnvironmentVariables#permit` (`filter_envs`/`filter_deploy_envs`/`filter_rollback_envs`) only filters the env hash passed in by the *caller* (e.g. a human triggering a task with extra vars); it is never consulted by `#interpolate`, which operates on a completely separate code path with its own unguarded `ENV[variable]` fallback.

### Impact Explanation
Whatever secret happens to be present in the Shipit application server's own process `ENV` — `GITHUB_TOKEN`, `GIT_ASKPASS`, or any other credential referenced by name in a shell step — can be exfiltrated into a task/deploy's captured output, which is readable by anyone with view access to that stack (repository viewer). If the Shipit installation uses a single shared GitHub token/App credential across all stacks for git operations, this lets an attacker who controls even just their own tracked repository/stack leak a host-wide credential that grants access far beyond their own repo, elevating this from self-harm to a Critical, cross-tenant credential exfiltration matching the stated impact category ("exfiltration of `GITHUB_TOKEN`... deploy-time secrets").

### Likelihood Explanation
Preconditions: (1) the Shipit host process's own `ENV` actually contains the named secret (plausible given `GIT_ASKPASS`/git-credential-handling references in the engine), (2) the attacker's `shipit.yml` content becomes the stack's `cached_deploy_spec` (requires their commits to be on the branch tracked by the stack, which normally requires either owning that stack/repo, or their content landing on the tracked branch through the ordinary git-sync/merge process), and (3) the resulting task/step is later executed. No forged webhook signature, no stolen session, and no privileged Shipit role is required — only the ability to author `shipit.yml` content that ends up in a stack's build/task steps.

### Recommendation
Remove or gate the `ENV[variable]` fallback in `EnvironmentVariables#interpolate` (`lib/shipit/environment_variables.rb`) so that only variables explicitly present in the caller-provided/whitelisted `@env` hash are ever substituted; any `$VAR` not present should either be left untouched/empty or raise, never resolve against the Shipit server process's own environment.

### Proof of Concept
```ruby
# test/unit/environment_variables_test.rb (conceptual addition)
test 'interpolate must not leak host process ENV for undeclared variables' do
  ENV['GITHUB_TOKEN'] = 'super-secret-token'
  command = Shipit::Command.new('echo $GITHUB_TOKEN', env: {}, chdir: '.')
  refute_includes command.interpolated_arguments.join(' '), 'super-secret-token'
ensure
  ENV.delete('GITHUB_TOKEN')
end
```
Equality asserted on both sides: `command.interpolated_arguments` (bytes handed to `PTY.spawn`) vs. `ENV['GITHUB_TOKEN']` (host secret) — currently equal (vulnerable); after the fix, they must diverge (the token must not appear).

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

**File:** app/models/shipit/task_definition.rb (L25-34)
```ruby
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

**File:** lib/shipit/task_commands.rb (L23-27)
```ruby
    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end
```

**File:** lib/shipit/command.rb (L51-55)
```ruby
    def interpolate_environment_variables(argument)
      return argument.map { |a| interpolate_environment_variables(a) } if argument.is_a?(Array)

      EnvironmentVariables.with(env).interpolate(argument)
    end
```

**File:** lib/shipit/command.rb (L85-98)
```ruby
    def start(&block)
      return if @started

      @control_block = block
      @out = @pid = nil
      FileUtils.mkdir_p(@chdir)
      begin
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
        child_in.close
      rescue Errno::ENOENT
        raise NotFound, "#{Shellwords.split(interpolated_arguments.first).first}: command not found"
      rescue Errno::EACCES
        raise Denied, "#{Shellwords.split(interpolated_arguments.first).first}: Permission denied"
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
