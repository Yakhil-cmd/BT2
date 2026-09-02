### Title
Untrusted `shipit.yml` review-check steps can exfiltrate arbitrary process environment variables via `EnvironmentVariables#interpolate`'s ENV fallback - ([File: lib/shipit/environment_variables.rb])

### Summary
`EnvironmentVariables#interpolate` resolves `$VAR` tokens in command strings by first checking the task's own `@env` hash and, if absent, falling back to the Ruby process's global `ENV`. Because `EphemeralCommitChecks#run` executes `review.checks`/`dependencies` steps taken directly from the pull request's own (attacker-controlled) `shipit.yml` with only the fixed `Shipit.env` hash as `@env`, an attacker can reference any variable name that happens to exist in the Shipit server process's real `ENV` and have its value echoed into task output visible on the PR/deploy page.

### Finding Description
The intended binding is: `set_of_variables_resolvable_by_interpolate == keys(@env passed for this step)`. The actual code breaks this: [1](#0-0) 
`argument.gsub(/(\$\w+)/) { ... @env.fetch(variable) { ENV[variable] } }` — when `variable` is not a key of `@env`, it silently falls through to the real process `ENV`, which is outside the engine's controlled/whitelisted set.

Path: `EphemeralCommitChecks#run` builds one `Command` per review/dependency step with `env: Shipit.env` (a fixed, operator-controlled hash: `{ 'SHIPIT' => '1' }.merge(secrets.env || {})`) and `chdir` pointing at a temporary checkout of the commit being reviewed: [2](#0-1) [3](#0-2) 
`DeploySpec::FileSystem.new(directory, stack)` reads `shipit.yml` from that same checked-out commit tree, so `review_checks`/`dependencies_steps` come straight from the PR author's own file: [4](#0-3) 
`Command#start` calls `interpolated_arguments`, which calls `EnvironmentVariables.with(env).interpolate`: [5](#0-4) [6](#0-5) 
The resulting escaped value is streamed and captured by `EphemeralCommitChecks#capture`/`#write`, which becomes the visible check output: [7](#0-6) [8](#0-7) 

An attacker who can push/open a PR from a fork simply adds to their own `shipit.yml`:
```yml
review:
  checks:
    - "echo $SOME_HOST_SECRET_ENV_VAR"
```
When Shipit schedules commit checks for that commit (`PerformCommitChecksJob` → `Commit#checks.run` → `EphemeralCommitChecks#run`), the step is run with `Shipit.env` as `@env`; since `SOME_HOST_SECRET_ENV_VAR` is not a key of `Shipit.env`, `EnvironmentVariables#interpolate` fetches it from the real process `ENV` and writes its value into the check output, viewable by the PR author on the deploy page.

Existing guards do not stop this: `EnvironmentVariables#permit` (a separate whitelist mechanism used elsewhere, e.g. for `machine.environment`) is never invoked in this path — `build_commands` passes `Shipit.env` directly to `Command.new`, bypassing any whitelist check, and `interpolate` itself has no whitelist logic at all.

One caveat: the specific claim that `GITHUB_TOKEN` is guaranteed to be present in the process `ENV` because of `Command::BASE_ENV` is not substantiated by this engine's own code — `BASE_ENV` (`unbundled_env.merge(...)`) is only used inside `Command#unbundled_env` for `PTY.spawn`'s child environment, and is not consulted by `interpolate`, which reads the literal global `ENV` directly. Nothing in this repository sets `ENV['GITHUB_TOKEN']`; the token is normally obtained via `Shipit.github.token` from encrypted credentials, not an OS environment variable. So exploitation of this exact variable name depends on unverified deployment configuration. The underlying flaw — arbitrary-name leakage of whatever *is* in the host process `ENV` (which commonly includes deployment secrets such as `DATABASE_URL`, `RAILS_MASTER_KEY`, `REDIS_URL`, cloud credentials, or, in some deployments, `GITHUB_TOKEN`) — is real and reachable pre-merge from an unprivileged fork PR.

### Impact Explanation
Any secret injected into the Shipit server process's environment (via `docker`/`kubernetes`/`systemd` env, `.env` files loaded at boot, etc.) is at risk of being echoed into task output readable by the PR author, without any merge or maintainer approval. Because `review.checks` runs pre-merge on untrusted fork commits, this is repeatable against every stack that has review checks/CI configured, by any GitHub user able to open a PR. This maps to the "exfiltration of ... deploy-time secrets" Critical category if the deployed Shipit process has sensitive values in `ENV` (a very common operational pattern), though the audit could not confirm that `GITHUB_TOKEN` specifically is one of them from code alone.

### Likelihood Explanation
Preconditions: `review.checks` (or `dependencies`) must be configured for the stack, and Shipit must schedule commit checks against fork/PR commits (standard usage per the documented review-check feature). Attacker cost is minimal — pushing a `shipit.yml` edit to a fork branch. Feasibility is high and fully repeatable per PR/commit; the only uncertainty is which secrets, if any, exist as OS-level environment variables in the specific deployment.

### Recommendation
Remove the `ENV[variable]` fallback in `EnvironmentVariables#interpolate` entirely; unresolved variables should raise/be left as literal text or empty, never silently source from the host process environment. If a fallback is desired, route it through `EnvironmentVariables#permit`'s whitelist so only variables explicitly declared for that task/step can be resolved.

### Proof of Concept
```ruby
# test/unit/environment_variables_test.rb (or command_test.rb)
test "interpolate does not leak process ENV variables absent from task env" do
  ENV['SOME_HOST_SECRET'] = 'super-secret-value'
  command = Shipit::Command.new('echo $SOME_HOST_SECRET', env: {}, chdir: '.')
  output = command.run
  refute_includes output, 'super-secret-value'
ensure
  ENV.delete('SOME_HOST_SECRET')
end
```
Before the fix, `EnvironmentVariables#interpolate` (`@env.fetch(variable) { ENV[variable] }`) causes this assertion to fail because the secret is fetched from process `ENV` and echoed; after removing the ENV fallback, the variable resolves to empty/unset and the secret never appears in command output.

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

**File:** app/models/shipit/ephemeral_commit_checks.rb (L14-20)
```ruby
    def run
      self.status = 'running'
      commands = StackCommands.new(stack)
      commands.with_temporary_working_directory(commit:) do |directory|
        deploy_spec = DeploySpec::FileSystem.new(directory, stack)
        capture_all(build_commands(deploy_spec.dependencies_steps, chdir: directory))
        capture_all(build_commands(deploy_spec.review_checks, chdir: directory))
```

**File:** app/models/shipit/ephemeral_commit_checks.rb (L49-51)
```ruby
    def build_commands(commands, chdir:)
      commands.map { |c| Command.new(c, env: Shipit.env, chdir:) }
    end
```

**File:** app/models/shipit/ephemeral_commit_checks.rb (L57-68)
```ruby
    def capture(command)
      command.start
      write("$ #{command}\n")
      command.stream! do |line|
        write(line)
      end
    rescue Command::Error => e
      write(e.message)
      raise
    ensure
      write("\n")
    end
```

**File:** app/models/shipit/deploy_spec.rb (L249-251)
```ruby
    def review_checks
      config('review', 'checks') || []
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

**File:** app/models/shipit/commit_checks.rb (L44-53)
```ruby
    def output(since: 0)
      Shipit.redis.getrange(key('output'), since, -1)
    end

    def write(output)
      Shipit.redis.pipelined do |pipeline|
        pipeline.append(key('output'), output)
        pipeline.expire(key('output'), OUTPUT_TTL)
      end
    end
```
