### Title
`EnvironmentVariables#interpolate` falls back to the Shipit host's own `ENV`, leaking process secrets into task output - ([File: lib/shipit/environment_variables.rb])

### Summary
`EnvironmentVariables#interpolate` substitutes `$WORD` tokens in a step string using `@env.fetch(variable) { ENV[variable] }`, where `@env` is the sanitized/whitelisted per-task environment but the fallback block reads directly from the Shipit process's real `ENV`. Any shipit.yml step (deploy, dependencies, fetch, rollback, or custom task) that references an environment variable name that is not defined in that task's `variables:`/`env:` will silently pull the Shipit host process's real value for that name instead of raising or substituting nothing.

### Finding Description
The broken binding: every `$WORD` substituted into a command **must** equal a value from the permitted/whitelisted task env (`TaskDefinition#filter_envs` → `EnvironmentVariables#permit`), i.e. `substituted_value == permitted_env[WORD]`. Instead, the actual code is: [1](#0-0) 

which evaluates to `substituted_value == permitted_env.fetch(WORD) { Shipit_process_ENV[WORD] }` — a strictly larger value space that includes the Shipit application server's own environment variables (`GITHUB_TOKEN`, `RAILS_MASTER_KEY`, database URLs, etc.), not just what was validated by `permit`.

Path: `Command#interpolate_environment_variables` calls `EnvironmentVariables.with(env).interpolate(argument)` for every argument of every step before spawning it via `PTY.spawn`: [2](#0-1) [3](#0-2) 

`interpolate` and `permit` are two entirely separate code paths on the same class — `permit` is used to build the sanitized env (e.g. via `TaskDefinition#filter_envs` / `DeploySpec#filter_deploy_envs`), but `interpolate` is invoked later on the *step string*, independently, and its `ENV[variable]` fallback bypasses whatever whitelist was applied when the env hash was constructed. `sanitize_env_vars` only restricts keys present in `@env`; it does nothing to prevent `interpolate`'s fallback from reading `ENV` directly.

Attacker's exact PR: attacker opens a PR from a fork/branch whose `shipit.yml` defines a `dependencies` (or `fetch`) step such as `["echo $GITHUB_TOKEN"]` without declaring `GITHUB_TOKEN` in `variables:`/`env:`. Since dependencies/fetch steps for a PR-associated stack are evaluated using that branch's `shipit.yml` via `DeploySpec::FileSystem`, when the resulting `Command` is built with the sanitized env (which does not contain `GITHUB_TOKEN`), `interpolate` looks it up, misses in `@env`, and falls back to the live Shipit process's `ENV['GITHUB_TOKEN']`, escaping it with `Shellwords.escape` and writing it into `interpolated_arguments`, which then get echoed to task output visible to the PR author/anyone who can view that task's stream.

None of the existing guards stop this: `permit`/`sanitize_env_vars` only validate keys explicitly present in the env hash being permitted — they never see or restrict what `interpolate`'s fallback does; `filter_envs`/`filter_deploy_envs`/`filter_rollback_envs` build the safe env but are bypassed by the independent `ENV[variable]` fallback inside `interpolate`.

### Impact Explanation
This exfiltrates real secrets from the Shipit host process (e.g. `GITHUB_TOKEN`, `RAILS_MASTER_KEY`, or any other credential exported into the Rails app's environment) into command/task output that is visible to the PR author and anyone who can view that repository's task streams. This matches the Critical category: "exfiltration of `GITHUB_TOKEN` ... or deploy-time secrets." It is repeatable against any stack/repository whose `shipit.yml` is attacker-controllable pre-merge (fork PRs), and once one secret name is guessed correctly (e.g. common names like `GITHUB_TOKEN`, `RAILS_MASTER_KEY`, `DATABASE_URL`, `SECRET_KEY_BASE`) it can be repeated for any variable present in the host's environment.

### Likelihood Explanation
Preconditions: the stack must use `DeploySpec::FileSystem`-driven pre-merge evaluation of a step (e.g. `dependencies_steps`/`fetch_deployed_revision_steps`) against the PR branch's `shipit.yml`, which is standard Shipit behavior for review/merge-request flows. The attacker needs no privileges beyond opening a PR/pushing a branch to a repo Shipit already tracks, and needs to guess or know the name of a real environment variable used by the Shipit host process — many of these names are conventional/well known (`GITHUB_TOKEN`, `RAILS_MASTER_KEY`, `SECRET_KEY_BASE`, `DATABASE_URL`). This is low-cost and fully repeatable.

### Recommendation
Remove the `ENV[variable]` fallback in `EnvironmentVariables#interpolate`; unresolved variables should either be left untouched, replaced with an empty string, or raise an error, but must never read from the Shipit process's own `ENV`:
```ruby
def interpolate(argument)
  return argument unless @env

  argument.gsub(/(\$\w+)/) do |variable|
    variable.sub!('$', '')
    Shellwords.escape(@env.fetch(variable, ''))
  end
end
```

### Proof of Concept
minitest test in the style of `test/unit/environment_variables_test.rb`:
```ruby
test "#interpolate does not leak values from the host process ENV" do
  ENV['GITHUB_TOKEN'] = 'super-secret-value'
  begin
    result = EnvironmentVariables.with({}).interpolate('echo $GITHUB_TOKEN')
    refute_includes result, 'super-secret-value'
  ensure
    ENV.delete('GITHUB_TOKEN')
  end
end
```
and at the `Command` level:
```ruby
test "Command#interpolated_arguments does not leak host ENV secrets" do
  ENV['GITHUB_TOKEN'] = 'super-secret-value'
  begin
    command = Shipit::Command.new('echo', '$GITHUB_TOKEN', chdir: Dir.tmpdir, env: {})
    refute_includes command.interpolated_arguments.join(' '), 'super-secret-value'
  ensure
    ENV.delete('GITHUB_TOKEN')
  end
end
```
Both assert the LHS (`interpolate`'s output) must equal only values sourced from the permitted `@env`, and fail against current code because the fallback substitutes the process `ENV` value instead.

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
