### Title
`EnvironmentVariables#interpolate` falls back to Shipit's process `ENV` for unset variable names in fork-controlled steps - (File: lib/shipit/environment_variables.rb)

### Summary
Under `provisioning_behavior=allow_with_label`, the deploy/rollback/task steps for a review stack are read from the PR's own `shipit.yml` (`DeploySpec::FileSystem`, reachable through `TaskCommands#perform`/`#install_dependencies`). Every step is interpolated via `Command#interpolated_arguments` → `EnvironmentVariables#interpolate`, and any `$VAR` token that is not a key already present in the merged task `env` hash silently resolves to Shipit's own OS-level `ENV[VAR]` instead of raising or being blanked, then gets `Shellwords.escape`d directly into the spawned command's argv.

### Finding Description
The broken binding: the code assumes `$VAR` in a step resolves only to values the operator explicitly placed in the task environment (`@stack.env`, `deploy_spec.machine_env`, `@task.env`, and the fixed keys set in `TaskCommands#env`), i.e. `interpolate($VAR) == task_env[VAR]`. In reality: [1](#0-0) 

`argument.gsub(/(\$\w+)/) { ... Shellwords.escape(@env.fetch(variable) { ENV[variable] }) }` — for any `VAR` not present as a key in `@env`, the fallback silently reads Shipit's actual process `ENV`, not the task's sandboxed env.

The merged env for task execution is built in: [2](#0-1) 

which merges `base_env` (containing `GITHUB_TOKEN`, `GITHUB_DOMAIN`), `@stack.env`, fixed keys, `deploy_spec.machine_env` (fork-controlled under `allow_with_label`), and `@task.env`. This is passed to `Command.new(command_line, env:, chdir: ...)` for every step in `deploy_steps`/`rollback_steps`/`dependencies_steps` — all of which, under `allow_with_label`, are sourced from the fork's `shipit.yml` via `DeploySpec::FileSystem` reading the checked-out fork commit. `Command#start` then calls `interpolated_arguments`, which runs every step string through `interpolate_environment_variables` before `PTY.spawn`: [3](#0-2) [4](#0-3) 

An attacker who can get a fork PR reviewed and labeled (the documented precondition for `allow_with_label`) writes a step such as `"echo $RAILS_MASTER_KEY"`, `"echo $SECRET_KEY_BASE"`, `"echo $DATABASE_URL"`, etc. None of these names are keys the engine populates in the merged task env, so `@env.fetch(variable) { ENV[variable] }` falls through to the Shipit host process's real `ENV`, and whatever secret the operator has configured there (DB creds, Rails master key, AWS keys, other app secrets) is escaped into the argv/stdout of the task, which is then visible in the task/build log output.

No existing guard prevents this: `EnvironmentVariables#permit` is only invoked for `filter_deploy_envs`/`filter_rollback_envs` (whitelisting user-supplied deploy/rollback *task* variables against `deploy_variables`/`rollback_variables`), not for interpolation of arbitrary `$VAR` tokens inside step strings, and `DeploySpec` performs no scoping of `machine.environment` or step text against an allow-list before it reaches `Command`.

### Impact Explanation
Any secret Shipit's own process happens to have in `ENV` (e.g. Rails `SECRET_KEY_BASE`, DB credentials, cloud provider keys, or other deploy-time secrets set as OS env vars on the host, not exclusively `GITHUB_TOKEN`) can be exfiltrated into task output readable by anyone with visibility of that review stack's task, purely by writing an `echo $VARNAME` step in the fork's `shipit.yml`. This is repeatable on every task run and, since it's driven purely by static step text in the checked-out repo, works against any repository/stack where `allow_with_label` review-stack provisioning is enabled and a PR carrying such a step gets labeled. This matches the Critical impact category (exfiltration of deploy-time secrets from the host).

### Likelihood Explanation
Requires: (1) the target repository configured with `provisioning_behavior=allow_with_label` for review stacks, and (2) a maintainer applying the trigger label to a PR (documented as required for that mode) so the fork's `shipit.yml`/steps get executed. Attacker cost is a normal PR + label from a maintainer (a routine review workflow action, not a privileged Shipit action). Attacker does not need to know secret values, only variable names, which can be guessed from common Rails/host conventions or discovered via other means; each guessed name is one line in the shipit.yml, fully repeatable.

### Recommendation
In `EnvironmentVariables#interpolate`, remove the fallback to the host process `ENV` for names not explicitly present in `@env` (e.g., raise, or substitute an empty string) so that fork-authored step text cannot read the Shipit process's own environment. Additionally, apply `permit`/allow-listing to `machine.environment` and to variable names referenced inside step strings, consistent with how `deploy_variables`/`rollback_variables` are already sanitized.

### Proof of Concept
```ruby
# test/unit/environment_variables_test.rb (concept)
test "interpolate must not fall back to the process ENV for unset names" do
  ENV['SHIPIT_SECRET_PROBE'] = 'super-secret-value'
  env = { 'SAFE' => 'ok' } # simulate task env with no SHIPIT_SECRET_PROBE key
  result = Shipit::EnvironmentVariables.with(env).interpolate('echo $SHIPIT_SECRET_PROBE')

  # Broken binding as equality:
  # expected: interpolate($VAR not in task env) == $VAR (untouched) OR raises
  # actual:   interpolate($VAR not in task env) == ENV[VAR]  <-- leak
  assert_not_equal "echo super-secret-value", result
ensure
  ENV.delete('SHIPIT_SECRET_PROBE')
end
```
A fuller integration test would build a `DeploySpec` from a fixture `shipit.yml` whose `deploy` steps contain `echo $SHIPIT_SECRET_PROBE`, run `TaskCommands#perform`, invoke `Command#start`, and assert the spawned argv/output contains the value of `ENV['SHIPIT_SECRET_PROBE']` rather than a placeholder — demonstrating leakage of a host-process secret through a fork-controlled step, with no live GitHub interaction required (only the checked-out `shipit.yml` fixture is needed to construct the `DeploySpec`).

### Citations

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
