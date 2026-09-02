### Title
`EnvironmentVariables#interpolate` falls back to Shipit's own process `ENV` for unset variables, leaking host secrets into task output - ([File: lib/shipit/environment_variables.rb])

### Summary
`EnvironmentVariables#interpolate` substitutes `$WORD` tokens in command-line arguments using `@env.fetch(variable) { ENV[variable] }`, which silently falls back to the Shipit host process's own `ENV` whenever the referenced variable is not present in the sanitized/whitelisted task environment. An attacker who controls a `shipit.yml` step (e.g. via a PR branch evaluated pre-merge) can reference a variable name that happens to match a real secret in Shipit's process environment (`GITHUB_TOKEN`, `RAILS_MASTER_KEY`, etc.) without declaring it in `env:`/`variables:`, causing that secret to be interpolated into the command and potentially echoed into task output.

### Finding Description
The intended binding is: every value substituted into a step for `$WORD` must come only from the explicitly permitted task env, i.e. `interpolated_value($WORD) == permitted_env[$WORD]` for all `$WORD`, and must be undefined/blank when `$WORD` is not in `permitted_env`. The actual code breaks this: [1](#0-0) 

`interpolate` does not consult `permit`/whitelist logic at all — it operates directly on whatever `@env` hash was passed into `EnvironmentVariables.with(env)`, and for any `$WORD` missing from that hash it falls back to `ENV[variable]`, i.e. Shipit's own process environment, not the task's declared/sanitized env.

The call path is `Command#interpolate_environment_variables` → `EnvironmentVariables.with(env).interpolate(argument)`, invoked from `Command#interpolated_arguments` right before `PTY.spawn`: [2](#0-1) [3](#0-2) 

Separately, `TaskDefinition#filter_envs` calls `EnvironmentVariables#permit`, which does enforce a whitelist — but that is a distinct method used to build the sanitized `env:` hash that flows into `Stack`/`Deploy`/`Task` records: [4](#0-3) [5](#0-4) 

Because `interpolate` and `permit` are independent code paths, whitelisting the env hash does not protect against a step that references an *undeclared* variable name — `interpolate` still falls through to `ENV[variable]` for anything not present in that (possibly already-whitelisted) hash, exposing whatever the Shipit Rails process itself has in its OS environment (credentials, Rails master key, GitHub App/token secrets, database URLs, etc.) to any step string containing a matching `$VARNAME` token.

Attacker exploit: attacker opens a PR from their fork and edits `shipit.yml` on that branch to add/modify a step (e.g. in `dependencies_steps` or `fetch_deployed_revision_steps`, which are evaluated against the PR branch's spec before merge) such as `echo $GITHUB_TOKEN`, without declaring `GITHUB_TOKEN` in `env:`/`variables:`. When that step is run by Shipit against the PR branch, `@env.fetch('GITHUB_TOKEN') { ENV['GITHUB_TOKEN'] }` returns Shipit's real `GITHUB_TOKEN` from its process environment, which is Shellwords-escaped and passed as a literal argument to the shell, then echoed into task output visible to the PR author.

No existing guard (`EnvironmentVariables#permit`, `TaskDefinition#filter_envs`, `DeploySpec` validations) intercepts this, because those guards apply to constructing the whitelist for *known* env hashes, not to the unconditional `ENV[variable]` fallback inside `interpolate`.

### Impact Explanation
This allows exfiltration of Shipit host process secrets (e.g. `GITHUB_TOKEN`, `RAILS_MASTER_KEY`, DB credentials, any secret exported into the Rails process's OS environment) into task output readable by an unprivileged PR author, for any repository where a PR-branch-evaluated shipit.yml step is executed. This matches the "Critical: exfiltration of GITHUB_TOKEN / deploy-time secrets" category and is repeatable against any stack whose spec allows steps to run against an unmerged PR branch (e.g. `dependencies_steps`, `fetch_deployed_revision_steps`).

### Likelihood Explanation
Preconditions are modest: the attacker needs to be able to modify `shipit.yml` on a branch that Shipit evaluates pre-merge (a normal PR-fork workflow supported by `DeploySpec::FileSystem`), and needs to guess/know the name of a real secret environment variable exported in the Shipit host process (common names like `GITHUB_TOKEN`, `RAILS_MASTER_KEY`, `DATABASE_URL` are reasonable guesses, and Shipit's own documentation/source references many of them). No Shipit credentials, GitHub App keys, or privileged roles are required — only the ability to open a PR, which matches the stated unprivileged attacker capability set.

### Recommendation
Remove the `ENV[variable]` fallback in `EnvironmentVariables#interpolate`; unset variables should raise or resolve to an empty string, never fall back to the host process environment:
```ruby
def interpolate(argument)
  return argument unless @env

  argument.gsub(/(\$\w+)/) do |variable|
    variable.sub!('$', '')
    Shellwords.escape(@env.fetch(variable, ''))
  end
end
```
Additionally, ensure `interpolate` only ever operates on an already-`permit`-filtered env hash so undeclared variables can never resolve to anything outside the task's explicit `variables:`/`env:` declarations.

### Proof of Concept
```ruby
# test/unit/environment_variables_test.rb (or command_test.rb)
test "interpolate does not leak host process ENV for unset variables" do
  ENV['GITHUB_TOKEN'] = 'super-secret-token'
  command = Shipit::Command.new('echo $GITHUB_TOKEN', chdir: '.', env: {})
  refute_includes command.interpolated_arguments.join(' '), 'super-secret-token'
ensure
  ENV.delete('GITHUB_TOKEN')
end
```
Expected (secure) behavior: assertion passes because the interpolated value is empty/blank. Current (vulnerable) behavior: assertion fails because `super-secret-token` is present in `interpolated_arguments`, proving the fallback to `ENV[variable]` leaks the host secret.

### Citations

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

**File:** lib/shipit/command.rb (L51-55)
```ruby
    def interpolate_environment_variables(argument)
      return argument.map { |a| interpolate_environment_variables(a) } if argument.is_a?(Array)

      EnvironmentVariables.with(env).interpolate(argument)
    end
```

**File:** lib/shipit/command.rb (L81-98)
```ruby
    def interpolated_arguments
      interpolate_environment_variables(@args)
    end

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

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
    end
```
