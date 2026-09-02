### Title
`Command#unbundled_env` lets attacker-declared `deploy.variables` named `PATH`/`IFS`/`BASH_ENV` override the spawned shell's real environment - ([File: lib/shipit/command.rb])

### Summary
Neither `VariableDefinition.new` (`app/models/shipit/variable_definition.rb`) nor `EnvironmentVariables#permit` (`lib/shipit/environment_variables.rb`) blacklist reserved/shell-special names, so a `shipit.yml` `deploy.variables` entry can be named `PATH`, `IFS`, or `BASH_ENV`. Once such a variable's value ends up in `@env`, `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) does `BASE_ENV.merge('PATH' => safe_path).merge(@env.stringify_keys)`, so the attacker-controlled key silently overwrites the safe `PATH` (or introduces `BASH_ENV`/`IFS`) in the hash handed to `PTY.spawn`, not merely substituted into argv.

### Finding Description
Broken binding (should hold, does not):
`unbundled_env['PATH'] == "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"` for every deploy, regardless of `deploy.variables` content.

Trace:
1. `DeploySpec#deploy_variables` builds `VariableDefinition` objects straight from repo-supplied config with no name filtering: `attributes.fetch('name')` only [1](#0-0) , and `deploy_variables` maps `config('deploy', 'variables')` directly [2](#0-1) .
2. `EnvironmentVariables#permit` (invoked via `DeploySpec#filter_deploy_envs`) only checks membership in `variable_definitions.map(&:name)` — a name of `PATH` is accepted like any other [3](#0-2) , [4](#0-3) .
3. `Command#unbundled_env` first sets a safe `PATH`, then unconditionally merges the whole `@env` hash on top: `.merge(@env.stringify_keys)` [5](#0-4) . This is the hash passed straight to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [6](#0-5) . If `@env` contains `'PATH'`/`'IFS'`/`'BASH_ENV'`, that value becomes the actual process environment for the spawned shell — this is categorically different from `EnvironmentVariables#interpolate`, which only does `Shellwords.escape` substitution inside a single `$WORD` token of argv [7](#0-6) .
4. No guard anywhere (`sanitize_env_vars`, `VariableDefinition#initialize`, `unbundled_env`) excludes `PATH`, `IFS`, `BASH_ENV`, or `ENV` from the merge.

I could not, within this session, fully re-confirm the exact call path that turns a PR's own `shipit.yml` `deploy.variables` definition into the runtime `@env` for an *automatic* (non-maintainer-triggered) deploy (i.e., whether `default_deploy_env` alone — without any operator/task-trigger action — is what feeds `Command`'s `env:` for review-app/CD deploys). That link (`Stack#deploy_variables` → `Deploy#variables` → wherever `Command.new(..., env: ...)` is constructed in `lib/shipit/task_commands.rb` / `lib/shipit/stack_commands.rb`) should be checked before treating this as fully reachable by an unauthenticated PR author versus requiring a maintainer to merge the `shipit.yml` change first. If Shipit only loads `deploy.variables` definitions from the target/default branch (post-merge), the practical severity is lower (it becomes a maintainer-controlled config quality issue, not a PR-author RCE). If review stacks build their `DeploySpec` from the PR's own head commit (a well-known Shipit review-app pattern), the vulnerability is directly attacker-reachable pre-merge.

### Impact Explanation
If reachable pre-merge (review-stack config sourced from the PR branch), an attacker's own fork commit can define `deploy.variables: [{name: PATH, default: "/tmp/evil:$PATH"}]` (or `BASH_ENV` pointing at a script), causing every subsequent unqualified binary invoked in that deploy step to resolve to attacker-planted binaries, or forcing bash to auto-source an attacker script on every interactive/login shell step — full command execution on the Shipit deploy host under whatever privileges the Shipit worker has. This is Critical (RCE on the deploy host via `Command`/`PTY.spawn`), and if the same host executes deploys for other stacks/repos, it risks tenant-crossing compromise.

### Likelihood Explanation
Preconditions: (1) the Shipit engine's own root-cause defect — `unbundled_env`'s unfiltered merge and the missing name blacklist — are both present as read from source, no speculation needed there. (2) Reachability without merge requires that the `DeploySpec`/`deploy.variables` used for that deploy come from an untrusted, attacker-controlled commit (fork/PR branch) rather than the protected default branch — this half of the chain I was not able to fully verify in this session due to running out of tool calls, so likelihood is **uncertain** pending that confirmation.

### Recommendation
In `VariableDefinition#initialize`, reject/blacklist reserved names (`PATH`, `IFS`, `BASH_ENV`, `ENV`, `LD_PRELOAD`, etc.). In `EnvironmentVariables#permit`/`sanitize_env_vars`, hard-fail if any allowed/declared variable name collides with this blacklist regardless of whitelist membership. In `Command#unbundled_env`, explicitly strip any of these reserved keys from `@env` before merging (`@env.stringify_keys.except(*RESERVED_ENV_KEYS)`), so `PATH` cannot be overridden by task/deploy variables under any circumstance.

### Proof of Concept
```ruby
# test/unit/command_test.rb (proof sketch)
test "unbundled_env does not allow @env to override PATH/BASH_ENV" do
  malicious_env = { 'PATH' => '/tmp/evil', 'BASH_ENV' => '/tmp/evil.sh' }
  command = Shipit::Command.new('echo', 'hi', chdir: '.', env: malicious_env)

  refute_equal '/tmp/evil', command.unbundled_env['PATH']
  assert_nil command.unbundled_env['BASH_ENV']
  assert_includes command.unbundled_env['PATH'], Shipit.shell_paths.join(':')
end
```
This currently fails against `lib/shipit/command.rb:103-105`, confirming the merge lets `@env` clobber `PATH`/introduce `BASH_ENV`.

### Citations

**File:** app/models/shipit/variable_definition.rb (L7-13)
```ruby
    def initialize(attributes)
      @name = attributes.fetch('name')
      @title = attributes['title']
      @default = attributes['default'].to_s
      @default_provided = attributes.key?('default')
      @select = attributes['select'].presence
    end
```

**File:** app/models/shipit/deploy_spec.rb (L120-122)
```ruby
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

**File:** lib/shipit/command.rb (L85-93)
```ruby
    def start(&block)
      return if @started

      @control_block = block
      @out = @pid = nil
      FileUtils.mkdir_p(@chdir)
      begin
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
        child_in.close
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```
