### Title
Deploy step `$WORD` interpolation falls back to the Shipit host process `ENV`, bypassing `DeploySpec#filter_deploy_envs` and leaking host secrets into deploy output - ([File: lib/shipit/environment_variables.rb])

### Summary
`EnvironmentVariables#permit` (used by `DeploySpec#filter_deploy_envs`) only sanitizes the explicit env *hash* supplied when a deploy is triggered; it never inspects the text of deploy step commands. `EnvironmentVariables#interpolate`, invoked later by `Command#interpolate_environment_variables` when building the actual shell command line, substitutes any `$WORD` token found in a step string, and falls back to Ruby's process-level `ENV[variable]` whenever the token isn't present in the task's filtered env. A PR author who controls their own repo's `shipit.yml` can therefore reference any `$WORD` matching a variable set in the Shipit host process's environment, and have its value literally spliced into the executed/echoed command, exfiltrating it into deploy output.

### Finding Description
The broken binding is: *every `$WORD` interpolated in a step string == a name present in `deploy_variables` approved for that stack*. This does not hold.

- `DeploySpec#filter_deploy_envs` calls `EnvironmentVariables.with(env).permit(deploy_variables)`, which only scrubs the explicit env hash (`sanitize_env_vars`) supplied via API/UI params (e.g., `Stack#build_deploy`). [1](#0-0) [2](#0-1) 
- Deploy step text itself comes straight from the repository's `shipit.yml` (`deploy.override`/`deploy.pre`/`deploy.post` etc.), fully attacker-controlled for their own stack, and is never passed through `permit`. [3](#0-2) 
- At execution time, `Command#interpolated_arguments` calls `interpolate_environment_variables(@args)`, which calls `EnvironmentVariables.with(env).interpolate(argument)` for each argument/step. [4](#0-3) [5](#0-4) 
- `interpolate` replaces every `$WORD` occurrence with `@env.fetch(variable) { ENV[variable] }` - i.e., if the token isn't one of the task's filtered/permitted variables, it silently falls back to the **Shipit Rails process's own `ENV`**. [6](#0-5) 
- Critically, the actual child process spawned via `PTY.spawn` does **not** inherit the full parent process environment; it receives only the explicitly constructed `unbundled_env` (`BASE_ENV` + `PATH` + the filtered `@env`). [7](#0-6)  This means running `env`/`printenv` inside a step only reveals the constrained subprocess environment, not the full host process environment - so `interpolate`'s `ENV[variable]` fallback is a materially different (and broader) information-disclosure primitive than what an attacker could already obtain from arbitrary shell execution inside the sandboxed child environment.

Exploit flow: a PR author (or repo owner controlling a fork/stack) edits `shipit.yml` in their own repository to add a deploy step such as `echo $SOME_HOST_SECRET_VAR_NAME`, without declaring `SOME_HOST_SECRET_VAR_NAME` in `deploy.variables`. When the stack deploys (self-triggered, since the attacker owns the repo/stack), `DeploySpec#deploy_steps` returns this string unchanged, `filter_deploy_envs` never sees it (it only filters the separate env-hash param), and at run time `Command#interpolate_environment_variables` fetches `ENV['SOME_HOST_SECRET_VAR_NAME']` from the Shipit host process and splices the literal secret value into the command line, which is then echoed into the deploy log stream, visible to the attacker in their own stack's deploy output.

None of the existing guards intercept this: `EnvironmentVariables#permit`/`sanitize_env_vars` operates on a hash, not on step strings; there is no whitelist check inside `interpolate`; `VariableDefinition`/`deploy_variables` declarations are irrelevant to what tokens `interpolate` will substitute.

### Impact Explanation
Any environment variable that happens to be set in the Shipit host/worker process (e.g., secrets injected via deployment tooling, `.env`, systemd unit files, container env, potentially `SECRET_KEY_BASE`, database/Redis URLs, or other operational secrets not intended for deploy-time use) can be exfiltrated into that attacker's own stack's deploy log, which the attacker (as the stack's controller) can read. This matches the "exfiltration of ... deploy-time secrets" Critical impact category. The blast radius is limited to whatever the attacker's own stack/deploy can read, but it defeats the intended isolation that `deploy_variables`/`filter_deploy_envs` is supposed to enforce for step-embedded variable references, and is repeatable on every deploy the attacker triggers, for any variable name they can guess is set in the host process's environment.

### Likelihood Explanation
Preconditions: the attacker needs a Shipit stack of their own (own repo connected as a stack) and edit access to that repo's `shipit.yml`, both of which are within the stated unprivileged-attacker capability (opening PRs / pushing to their own repo). Attacker cost is minimal - a one-line `shipit.yml` change referencing a guessed/known environment variable name and triggering a deploy. Feasibility depends on the attacker knowing or guessing meaningful variable names present in the Shipit host process's `ENV` (not disclosed by this bug itself), which somewhat limits practical severity but does not require any secret, session, or privileged role.

### Recommendation
Make `EnvironmentVariables#interpolate` only substitute from the already-permitted/filtered `@env` hash and never fall back to the process `ENV`; unknown `$WORD` tokens should be left literal or raise, matching the same whitelist enforced by `permit`/`deploy_variables`.

### Proof of Concept
```ruby
# test/unit/environment_variables_test.rb (or command_test.rb)
test 'interpolate does not leak host process ENV for undeclared variables' do
  ENV['SECRET_NOT_IN_SPEC'] = 'super-secret-value'
  begin
    variable_definitions = [] # nothing declared in deploy.variables
    filtered_env = Shipit::EnvironmentVariables.with({}).permit(variable_definitions) # => {}

    command = Shipit::Command.new(
      'echo', '$SECRET_NOT_IN_SPEC',
      env: filtered_env,
      chdir: Dir.tmpdir
    )
    output = command.run

    # Binding under test: every $WORD interpolated in a step == a name in deploy_variables.
    # This currently FAILS: the fallback to ENV leaks the secret despite it not being permitted.
    assert_no_match(/super-secret-value/, output)
  ensure
    ENV.delete('SECRET_NOT_IN_SPEC')
  end
end
```
This currently fails against the unpatched code (the output contains `super-secret-value`), demonstrating that `filter_deploy_envs`/`permit` provides no protection against step-text `$WORD` references falling back to the host process `ENV` in `EnvironmentVariables#interpolate`.

### Citations

**File:** app/models/shipit/deploy_spec.rb (L110-122)
```ruby
    def deploy_steps
      around_steps('deploy') do
        config('deploy', 'override') { discover_deploy_steps }
      end
    end

    def deploy_steps!
      deploy_steps || cant_detect!(:deploy)
    end

    def deploy_variables
      Array.wrap(config('deploy', 'variables')).map(&VariableDefinition.method(:new))
    end
```

**File:** app/models/shipit/deploy_spec.rb (L174-176)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
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

**File:** lib/shipit/command.rb (L81-83)
```ruby
    def interpolated_arguments
      interpolate_environment_variables(@args)
    end
```

**File:** lib/shipit/command.rb (L92-105)
```ruby
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
