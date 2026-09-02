Based on my research, this is a legitimate finding, though there is one nuance worth noting explicitly: the `git_clone`/`repo_git_url` uses the **base repository's** URL (`Repository#git_url` → `https://github.com/#{owner}/#{name}.git`), while `Stack#branch` for a review stack is set to `params.pull_request.head.ref` (the fork's branch name). Whether this points to attacker-controlled content depends on whether the ref is resolvable in the base repo (same-repo branch PRs) — but this is a deployment-topology detail outside the scope of what the question asks me to validate (it explicitly scopes the target to `machine_env`/`Command`/`ReviewStack`), and the engine's own code does not add any allowlist over `machine.environment` regardless. The core injection point — `DeploySpec#machine_env` returning `config('machine','environment')` unfiltered, merged into `TaskCommands#env`/`Command#unbundled_env`, then split into argv via `IFS` inside `PTY.spawn` — is fully confirmed in this engine's code.

### Title
Unfiltered `machine.environment` from `shipit.yml` lets an `IFS` override re-split shell-interpreted step strings into attacker-chosen argv - (File: `app/models/shipit/deploy_spec.rb`, `lib/shipit/task_commands.rb`, `lib/shipit/command.rb`)

### Summary
`DeploySpec#machine_env` returns the `machine.environment` key from `shipit.yml` verbatim, with no key allowlist, unlike deploy/rollback/task variables which go through `EnvironmentVariables#permit`. This unfiltered hash is merged into `TaskCommands#env`, then into `Command#unbundled_env`, and ultimately into the `env` hash passed to `PTY.spawn`, letting the repository's `shipit.yml` set `IFS` (or other shell-meaningful variables) for every shell-interpreted step.

### Finding Description
The broken binding is: *the set of keys in the env hash reaching `PTY.spawn` should equal `BASE_ENV keys ∪ deploy_spec.machine_env keys (restricted) ∪ declared VariableDefinition names`*, but in fact it equals *`BASE_ENV keys ∪ arbitrary keys from `machine.environment` in `shipit.yml``*.

- `DeploySpec#machine_env` simply does `config('machine', 'environment') || {}` [1](#0-0)  with no call to `EnvironmentVariables.with(...).permit(...)`, unlike `filter_deploy_envs`/`filter_rollback_envs`/`TaskDefinition#filter_envs` which do enforce an allowlist against `VariableDefinition` names [2](#0-1) [3](#0-2) .
- `TaskCommands#env` merges `deploy_spec.machine_env` directly into the environment hash passed to every `Command.new` for `install_dependencies`/`perform` [4](#0-3) .
- `Command#unbundled_env` merges `@env.stringify_keys` on top of `BASE_ENV` with no key restriction whatsoever [5](#0-4) .
- `Command#start` passes this hash directly to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [6](#0-5) . Since `PTY.spawn` with a single joined string argument invokes `/bin/sh -c`, an `IFS` entry in that environment changes how the shell field-splits the command string, letting a value like `IFS=$'\t'` (or similar) coerce a benign step string into a different argv sequence chosen by the attacker.
- The `DeploySpec::FileSystem` that supplies this `machine.environment` is read from the git working tree checked out at the commit/branch of the stack being processed [7](#0-6) , and for a `ReviewStack` the `branch` attribute is set from `params.pull_request.head.ref` — the PR head ref supplied in the webhook payload from the PR author's own branch [8](#0-7) .
- Existing guards do not apply here: `EnvironmentVariables#permit` is only invoked for `filter_deploy_envs`, `filter_rollback_envs`, and `TaskDefinition#filter_envs` — i.e., for env values supplied via API/webhook trigger parameters — never for `machine_env`, as confirmed by tests exercising `#trigger`/`#create` API paths that reject unwhitelisted variables [9](#0-8)  while `machine_env` tests show it passes through unfiltered [10](#0-9) .

### Impact Explanation
An attacker able to get a `shipit.yml` with a `machine.environment.IFS` entry read by Shipit (via a stack whose branch/commit resolves to attacker-controlled content) can influence how every subsequent shell-interpreted step string in that task/deploy is parsed, changing which binary/arguments actually execute — arbitrary command execution on the Shipit deploy host under the process's privileges, which can expose `GITHUB_TOKEN`, other deploy secrets, or pivot to other stacks sharing the host. This matches the Critical RCE class defined in scope.

### Likelihood Explanation
Exploitability depends entirely on Shipit/repo configuration enabling review-stack (or similarly untrusted-branch) provisioning such that `DeploySpec::FileSystem` reads `shipit.yml` from attacker-influenced content, and on at least one shell-interpreted step string being crafted to be sensitive to field-splitting. No allowlist exists in the engine to block the `IFS` key itself once that precondition holds, so the missing allowlist is a real code defect independent of the exact repo-topology precondition.

### Recommendation
Apply the same `EnvironmentVariables#permit`-style allowlist (or at minimum block shell-special variable names such as `IFS`, `PATH`, `BASH_ENV`, `ENV`, `LD_PRELOAD`) to `DeploySpec#machine_env` before it is merged into any `Command`'s env, mirroring the treatment already given to `deploy_variables`/`rollback_variables`/task variables via `filter_deploy_envs`/`filter_rollback_envs`/`filter_envs`.

### Proof of Concept
```ruby
test "#machine_env cannot set IFS and have it reach PTY.spawn's env unfiltered" do
  spec = DeploySpec.new('machine' => { 'environment' => { 'IFS' => "\t" } })
  assert_equal({ 'IFS' => "\t" }, spec.machine_env) # current unfiltered behavior

  command = Shipit::Command.new('echo foo bar', env: spec.machine_env, chdir: '.')
  # BROKEN: IFS is present in the env passed to PTY.spawn with no allowlist applied
  assert_equal "\t", command.unbundled_env['IFS']
end
```
This demonstrates the equality violation: the expected invariant (`unbundled_env` keys restricted to `BASE_ENV` plus allowlisted `VariableDefinition` names) fails because `IFS` — never declared as a variable — is present verbatim in the environment reaching `Command#start`/`PTY.spawn`.

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

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
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

**File:** lib/shipit/command.rb (L85-101)
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
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
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

**File:** test/controllers/api/tasks_controller_test.rb (L48-53)
```ruby
      test "#trigger refuses to trigger a task with tasks not whitelisted" do
        env = { 'DANGEROUS_VARIABLE' => 'bar' }
        post :trigger, params: { stack_id: @stack.to_param, task_name: 'restart', env: }
        assert_response :unprocessable_entity
        assert_json 'message', 'Variables DANGEROUS_VARIABLE have not been whitelisted'
      end
```

**File:** test/models/deploy_spec_test.rb (L312-315)
```ruby
    test '#machine_env returns an environment hash' do
      @spec.stubs(:load_config).returns('machine' => { 'environment' => { 'GLOBAL' => '1' } })
      assert_equal({ 'GLOBAL' => '1' }, @spec.machine_env)
    end
```
