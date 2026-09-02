### Title
Task/deploy `$VARIABLE` interpolation falls back to the deploy host's real process environment, bypassing the `shipit.yml` variable whitelist - (File: `lib/shipit/environment_variables.rb`, `lib/shipit/command.rb`)

### Summary
`shipit.yml` restricts which environment variable *names* a deployer can set for a deploy/task via `deploy.variables` / `tasks.<name>.variables`, enforced by `EnvironmentVariables#permit`. However, `Command#interpolated_arguments` calls `EnvironmentVariables#interpolate`, which for any `$VAR` reference in a step string that is **not** present in the permitted/sanitized env hash silently falls back to the real host process environment (`ENV[variable]`). This breaks the binding "environment key permitted (via `shipit.yml` variable whitelist)" = "environment key spawned into the executed shell command," letting a `shipit.yml` author reference and exfiltrate arbitrary host process environment variables (e.g. `GITHUB_TOKEN`, DB credentials, other secrets injected into the Shipit worker process) into the deploy/task output, which any authorized deployer can read.

### Finding Description
`EnvironmentVariables#permit` is the whitelist gate used everywhere a caller-supplied `env` hash is accepted (`Stack#trigger_task`, `Stack#build_deploy`, `TaskDefinition#filter_envs`): [1](#0-0) [2](#0-1) 

This whitelist only constrains the hash of *values supplied by the API/user* against the declared `variables:` list in `shipit.yml`. But the *same class* exposes `interpolate`, used when expanding `$VAR` references inside step command strings (e.g. `script/failover $POD_ID`): [3](#0-2) 

Note line 25: `Shellwords.escape(@env.fetch(variable) { ENV[variable] })` — if the referenced variable name is not a key in `@env` (the task/deploy's constructed env hash, which is whitelist-filtered), it falls back to `ENV[variable]`, i.e., the **real process environment of the Shipit Rails/worker process**, with no whitelist check at all.

This is invoked from `Command#interpolate_environment_variables` / `#interpolated_arguments`, which is used to build the actual argv passed to `PTY.spawn` when a step is executed: [4](#0-3) [5](#0-4) 

The `shipit.yml` `tasks.<name>.steps` and `deploy`/`rollback` step strings are attacker-controllable by anyone with GitHub write/PR access to the repo whose `shipit.yml` Shipit reads (see `DeploySpec::FileSystem#load_config`, which reads `shipit.yml` straight from the checked-out repository) — this is exactly the same class of "field acted upon but not bound to the intended trust boundary" as the reported `ForkDAODeployer` issue: the set of variable *names* that are supposed to be controlled (whitelisted in `shipit.yml`'s `variables:` section) is not the same set of names that can actually be dereferenced and spawned into the running shell command.

### Impact Explanation
Any user who can edit `shipit.yml` on the tracked branch (i.e., anyone with write/merge access to the repository — the same trust level required to define `deploy`/`task` steps at all) can add a step like:
```yaml
tasks:
  leak:
    action: "Leak"
    steps:
      - "echo $GITHUB_TOKEN"
```
Because `GITHUB_TOKEN` (or any other secret injected as a process environment variable into the Shipit Sidekiq/worker container — a common operational pattern) is not declared under `variables:`, `@env` (the whitelisted hash) won't contain it, so `interpolate` falls through to the real `ENV['GITHUB_TOKEN']` and echoes it into the task output, which is visible to every user with `deploy:stack` permission on the stack (broader than the `shipit.yml` editor). This matches the report's Critical bucket "exfiltration of `GITHUB_TOKEN`... or `api_clients_secret`" if such secrets are present in the process environment of the deploy host — a realistic deployment pattern since Shipit itself reads `SHIPIT_DRY_RUN` and other `ENV` values directly in the same process (see `TaskExecutionStrategy::Default#perform_task` reading `ENV['SHIPIT_DRY_RUN']`), showing the app's own convention of using process env for control/config, i.e., secrets living in `ENV` is plausible.

### Likelihood Explanation
Likelihood is limited to actors who already have write access to `shipit.yml` in the tracked repo (a meaningfully privileged position, similar to the report's "operational mistake or malicious intent" framing for who configures fork parameters). It requires no additional API token, webhook secret, or session compromise beyond normal repository write access already trusted to define deploy steps — so it is a genuine escalation from "can edit deploy scripts" to "can read arbitrary host process environment variables," which is not something `variables:` whitelisting was designed to allow.

### Recommendation
`EnvironmentVariables#interpolate` should never silently fall back to the real process `ENV`. It should only resolve `$VAR` references against the same whitelisted/sanitized hash used by `permit`, and raise `NotPermitted` (or otherwise fail closed) for any reference to a name not explicitly declared in `variables:`.

### Proof of Concept
1. Add to the repository's `shipit.yml`:
```yaml
tasks:
  leak:
    action: "Leak Host Secret"
    steps:
      - "echo $GITHUB_TOKEN"
```
(no `variables:` entry declaring `GITHUB_TOKEN`).
2. Trigger the `leak` task via the UI/API as any user with `deploy:stack` permission (`POST /stacks/:id/tasks` or `api/tasks#trigger`).
3. `Stack#trigger_task` builds `env = definition.filter_envs(env)` (whitelisted, empty here) and enqueues the task.
4. During execution, `TaskCommands#perform` builds a `Command` with the whitelisted `env` and calls `.perform`; `Command#start` calls `interpolated_arguments`, which calls `EnvironmentVariables.with(env).interpolate("echo $GITHUB_TOKEN")`.
5. Because `GITHUB_TOKEN` is absent from the whitelisted `@env`, `interpolate` executes `ENV.fetch('GITHUB_TOKEN')` against the Shipit worker process's real environment and substitutes it into the spawned shell command, printing the secret in the task log visible to the triggering user (and anyone who can view the task).

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

**File:** lib/shipit/environment_variables.rb (L35-44)
```ruby
    def sanitize_env_vars(variable_definitions)
      allowed_variables = variable_definitions.map(&:name)

      allowed, disallowed = @env.partition { |k, _| allowed_variables.include?(k) }.map(&:to_h)

      error_message = "Variables #{disallowed.keys.to_sentence} have not been whitelisted"
      raise NotPermitted, error_message unless disallowed.empty?

      allowed
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
