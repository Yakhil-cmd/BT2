### Title
Fork PR can inject arbitrary `machine.environment` variables (including `BASH_ENV`) into deploy/task command environment via `shipit.yml` — (File: app/models/shipit/deploy_spec.rb, lib/shipit/task_commands.rb, lib/shipit/command.rb)

### Summary
`DeploySpec#machine_env` returns the `machine.environment` section of `shipit.yml` verbatim, and `TaskCommands#env` merges it unfiltered into the environment hash passed to `Command.new`, which `Command#unbundled_env` merges into the hash given to `PTY.spawn`. Unlike `deploy.variables`/`rollback.variables`/task `variables`, which are passed through `EnvironmentVariables#permit` with an explicit whitelist, `machine_env` has no such filtering, so any key/value pair (including `BASH_ENV`) set under `machine.environment` in `shipit.yml` reaches the spawned shell process.

### Finding Description
The broken binding: `TaskCommands#env` should guarantee `env_reaching_PTY.spawn ⊆ Shipit.env ∪ Shipit-generated keys ∪ whitelisted deploy/rollback/task variables`, but in fact `env_reaching_PTY.spawn ⊇ deploy_spec.machine_env` verbatim, with no whitelist:

- `DeploySpec#machine_env` at `app/models/shipit/deploy_spec.rb:69-71` returns `config('machine', 'environment') || {}` with no sanitization.
- `TaskCommands#env` at `lib/shipit/task_commands.rb:33-48` does `.merge(deploy_spec.machine_env)` directly into the hash handed to `Command.new(command_line, env:, chdir:)`.
- `Command#unbundled_env` at `lib/shipit/command.rb:103-105` does `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)`, and `Command#start` (`lib/shipit/command.rb:85-101`) calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`.
- Contrast with `filter_deploy_envs`/`filter_rollback_envs`/`TaskDefinition#filter_envs` (`app/models/shipit/deploy_spec.rb:174-180`, `app/models/shipit/task_definition.rb:63-65`), which call `EnvironmentVariables.with(env).permit(variable_definitions)` (`lib/shipit/environment_variables.rb:13-18`) to reject any key not in an explicit whitelist — this whitelist mechanism exists specifically for attacker/user-supplied env values, but it is never applied to `machine.environment`.
- The README itself documents `machine.environment` as attacker-facing configuration ("contains the extra environment variables that you want to provide during task execution") with no restriction on variable names, confirming this is treated as a legitimate, unfiltered feature rather than an accidental omission — i.e., `BASH_ENV` is not specifically blocked by any schema or key denylist.

The `DeploySpec::FileSystem` (`app/models/shipit/deploy_spec/file_system.rb`) loads this configuration from the `shipit.yml` present in the checked-out working directory of the task/deploy, which for a `ReviewStack` corresponds to the commit on the PR's head branch (`stack_attributes[:branch] = params.pull_request.head.ref`, set in `review_stack_adapter.rb:87-94`).

**Caveat on reachability for fork PRs specifically:** I was unable to confirm within the available index whether, for review stacks created from *forked* repositories, the git fetch/clone in `StackCommands`/`TaskCommands` (`lib/shipit/task_commands.rb:61-73`, `lib/shipit/stack_commands.rb`) actually retrieves the commit content from the fork rather than from `@stack.repository.git_url` (the base repo). The `clone`/`checkout` code always uses `@stack.git_path` / `@stack.repo_git_url` / `@stack.branch`, which map to the *base* repository's git URL plus a branch name taken from `pull_request.head.ref`. For a true cross-fork PR, that branch name generally does not exist on the base repository unless GitHub-specific `refs/pull/<n>/head` handling is used elsewhere, which I did not find evidence of in the reachable code. This means the concrete claim "unprivileged fork PR" may not hold as stated — same-repository (non-fork) branch PRs are more clearly and directly exploitable through this path, since `stack.branch` and `repo_git_url` line up correctly with the base repo in that case.

### Impact Explanation
If reachable, this allows a user who can get a `shipit.yml` merged onto a branch that becomes a Shipit stack's tracked branch (definitely true for same-repo branches/PRs, uncertain for pure forks per above) to set `BASH_ENV=/tmp/evil.sh` or any other environment variable and have it passed into every subsequent `PTY.spawn`-based command execution for that stack (deploys, rollbacks, custom tasks, dependency installation). If `/tmp/evil.sh` (or any writable/attacker-controlled path) is bash-sourced during a later non-interactive step invocation, this is Remote Code Execution on the Shipit deploy host — Critical impact, matching the RCE category via `Command`/`PTY.spawn`. Blast radius is scoped to the stack/environment whose `shipit.yml` was modified, but repeatable on every task run against the affected stack, and any user with commit access to write `shipit.yml` on a stack's tracked branch can leverage it.

### Likelihood Explanation
- Requires the attacker's `shipit.yml` (with the malicious `machine.environment`) to be present on the exact branch tracked by the stack at the moment a task/deploy runs against it. This is straightforward for direct-push/PR-into-tracked-branch scenarios.
- Requires the target host's `bash` (or whatever shell interprets `BASH_ENV`) to source the referenced file when running non-interactive `shipit.yml` steps; also requires the attacker (or some other process) to be able to place content at the referenced path (e.g., `/tmp/evil.sh`) on the deploy host before the step runs — for the specific concrete payload `/tmp/evil.sh`, this needs an additional write primitive to that path, which is not itself established here.
- Whether this is reachable purely from a *fork* PR (as opposed to a same-repo branch/PR) depends on the exact git-fetch mechanics for `ReviewStack`, which I could not fully verify from the indexed code.

### Recommendation
Whitelist or sanitize `machine.environment` the same way `deploy.variables`/`rollback.variables`/task `variables` are sanitized via `EnvironmentVariables#permit`, or explicitly strip/deny dangerous shell-influencing variable names (`BASH_ENV`, `ENV`, `LD_PRELOAD`, `PROMPT_COMMAND`, `IFS`, etc.) before merging `deploy_spec.machine_env` into the command environment in `TaskCommands#env`.

### Proof of Concept
Minitest plan (unit-level, does not require live GitHub):
```ruby
test "#env merges shipit.yml machine.environment verbatim including BASH_ENV" do
  deploy_spec = stub(
    dependencies_steps!: [],
    deploy_steps!: [],
    machine_env: { 'BASH_ENV' => '/tmp/evil.sh' },
    directory: nil,
    clear_working_directory?: true
  )
  commands = DeployCommands.new(shipit_deploys(:shipit_pending))
  commands.stubs(:deploy_spec).returns(deploy_spec)

  env = commands.env
  assert_equal '/tmp/evil.sh', env['BASH_ENV']

  command = Command.new('true', env:, chdir: '.')
  assert_equal '/tmp/evil.sh', command.unbundled_env['BASH_ENV']
end
```
This demonstrates the equality `deploy_spec.machine_env['BASH_ENV'] == command.unbundled_env['BASH_ENV']` holds with no filtering step in between, confirming the env value flows unmodified from `shipit.yml` into the hash passed to `PTY.spawn`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
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

**File:** lib/shipit/command.rb (L85-105)
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
      @started = true
      self
    end

    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L87-94)
```ruby
          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** lib/shipit/stack_commands.rb (L17-35)
```ruby
    def fetch_commit(commit)
      create_directories
      if valid_git_repository?(@stack.git_path)
        git('fetch', 'origin', *quiet_git_arg, '--tags', '--force', commit.sha, env:, chdir: @stack.git_path)
      else
        @stack.clear_git_cache!
        git_clone(@stack.repo_git_url, @stack.git_path, branch: @stack.branch, env:, chdir: @stack.deploys_path)
      end
    end

    def fetch
      create_directories
      if valid_git_repository?(@stack.git_path)
        git('fetch', 'origin', *quiet_git_arg, '--tags', '--force', @stack.branch, env:, chdir: @stack.git_path)
      else
        @stack.clear_git_cache!
        git_clone(@stack.repo_git_url, @stack.git_path, branch: @stack.branch, env:, chdir: @stack.deploys_path)
      end
    end
```

**File:** app/models/shipit/stack.rb (L391-405)
```ruby
    delegate :owner, to: :repository, prefix: :repo
    delegate :http_url, to: :repository, prefix: :repo
    delegate :git_url, to: :repository, prefix: :repo

    def base_path
      @base_path ||= Rails.root.join('data', 'stacks', repo_owner, repo_name, environment)
    end

    def deploys_path
      @deploys_path ||= base_path.join("deploys")
    end

    def git_path
      @git_path ||= base_path.join("git")
    end
```
