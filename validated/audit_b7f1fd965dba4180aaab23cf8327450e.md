## Analysis

The Mantra bug is a **binding break between what is checked and what actually executes**: `belief_price` is the user's approved price bound, but the swap that actually executes uses only the pool's live spot price, silently voiding the user's protection. The strongest analog in Shipit is exactly the pattern the rules flag as "an environment key permitted versus an environment key spawned."

### Title
Unwhitelisted `$VAR` interpolation in shell commands bypasses environment scrubbing, exfiltrating host secrets (`SECRET_KEY_BASE`, `GITHUB_APP_ID`, etc.) into deploy/task output - (File: `lib/shipit/environment_variables.rb`, `lib/shipit/command.rb`)

### Summary
Shipit deliberately scrubs the spawned deploy/task subprocess's environment down to a `BASE_ENV` that nils out every OS environment variable that isn't part of Bundler's own env, specifically to prevent host secrets from leaking into deploy scripts. However, `Command#interpolate_environment_variables` performs its own `$VARNAME` substitution *before* spawning, and for any variable name not present in the whitelisted/merged `env` hash, it falls back to reading directly from the live process `ENV` — the very values the spawn-time scrubbing was designed to hide — and bakes the literal value into the command string.

### Finding Description
`EnvironmentVariables#permit` is the enforcement point that whitelists which variables a user may *set* for a deploy/task (`lib/shipit/environment_variables.rb:13-18`), and `TaskDefinition#filter_envs` / `Stack#filter_deploy_envs` use it to sanitize user-supplied env (`app/models/shipit/task_definition.rb:63-65`, `app/models/shipit/deploy_spec.rb:174-176`). This is the "permitted" side of the binding.

Separately, when a `Command` is spawned, its arguments are run through `interpolate_environment_variables` → `EnvironmentVariables#interpolate`: [1](#0-0) 

```ruby
def interpolate(argument)
  return argument unless @env
  argument.gsub(/(\$\w+)/) do |variable|
    variable.sub!('$', '')
    Shellwords.escape(@env.fetch(variable) { ENV[variable] })
  end
end
```

If `$VARNAME` is not a key in the merged, whitelisted `@env` hash, it falls back to `ENV[variable]` — the Shipit *process's own* environment, not the deploy/task's sanitized env. This is invoked at spawn time: [2](#0-1) 

Meanwhile the child process's environment is explicitly scrubbed for this exact reason: [3](#0-2) [4](#0-3) 

`BASE_ENV` nils out any key not in Bundler's unbundled env before the child is spawned, meaning the child process itself cannot simply read `$SECRET_KEY_BASE`/`$GITHUB_APP_ID` etc. from its own inherited environment. But `interpolate_environment_variables` runs on the raw command string *before* this scrubbing takes effect, substituting the literal value from the live Ruby `ENV` directly into the argument string that gets passed to `PTY.spawn`. Since production `config/secrets.yml` (see `template.rb:97-113`) sources `SECRET_KEY_BASE`, `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, etc. straight from `ENV`, these are live in the Shipit process's `ENV` and thus reachable via this fallback.

The binding that's broken: the set of environment keys a deploy/task is **permitted** to reference (`deploy_variables`/`task.definition.variables`, enforced by `EnvironmentVariables#permit`) is not the same set of keys that actually get **spawned**/substituted into command lines (`EnvironmentVariables#interpolate`, which silently widens scope to the entire host process `ENV`).

### Impact Explanation
Any `shipit.yml` step (deploy, rollback, task, dependencies, review checks — all built via `Command.new(command_line, env:, chdir:)` in `lib/shipit/task_commands.rb` and `lib/shipit/stack_commands.rb`) that references an unwhitelisted `$VARNAME` matching a real host process environment variable will have that secret value substituted verbatim into the shell command that is executed and streamed to task/deploy output, visible to any user with read access to that stack's task output. Depending on the deployment's `config/secrets.yml`, this can include `SECRET_KEY_BASE`, GitHub App credentials, database URLs, or other process-level secrets — satisfying the Critical impact bar of "exfiltration of ... `api_clients_secret`" or equivalent credential material, since it defeats a control (`BASE_ENV` scrubbing) purpose-built to prevent exactly this leak.

### Likelihood Explanation
Exploitability depends on a `shipit.yml` (or task definition) step containing a reference to `$SOME_HOST_ENV_VAR` — something a repository maintainer authoring `shipit.yml` could do intentionally or accidentally (e.g. copy-pasting a script that references `$PATH`-adjacent or CI-style variable names that happen to collide with host secrets). It requires control over `shipit.yml` on a deployed ref, which is a lower bar than requiring an actual Shipit session/token, and the resulting leak reaches any authenticated stack viewer, not just the author.

### Recommendation
Make `EnvironmentVariables#interpolate` fail closed: raise `NotPermitted` (or leave the `$VAR` unexpanded) for any variable not present in the same whitelist enforced by `permit`, rather than falling back to the live process `ENV`. The interpolation and permission-check code paths should share one source of truth for "keys this command is allowed to see."

### Proof of Concept
1. Deploy host is started with `SECRET_KEY_BASE=<sensitive>` in its environment (as templated in `template.rb`).
2. A stack's `shipit.yml` defines a deploy step: `deploy: - './notify.sh $SECRET_KEY_BASE'`.
3. `SECRET_KEY_BASE` is not part of `deploy_variables`, `stack.env`, or `deploy_spec.machine_env`, so it is absent from the merged `env` hash built in `lib/shipit/task_commands.rb:33-48`.
4. On deploy, `Command#interpolated_arguments` calls `EnvironmentVariables#interpolate`, which falls back to `ENV['SECRET_KEY_BASE']` and substitutes the real secret into the argument passed to `PTY.spawn`.
5. The literal secret value is now present in the spawned process's argv (observable via `ps`, and via whatever `notify.sh` does with its argument, e.g. logging or echoing it into the streamed task output visible in the Shipit UI). [1](#0-0) [3](#0-2) [5](#0-4) [6](#0-5)

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

**File:** lib/shipit/command.rb (L17-18)
```ruby
    unbundled_env = Bundler.respond_to?(:unbundled_env) ? Bundler.unbundled_env : Bundler.clean_env
    BASE_ENV = unbundled_env.merge((ENV.keys - unbundled_env.keys).map { |k| [k, nil] }.to_h)
```

**File:** lib/shipit/command.rb (L81-105)
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

    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
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
