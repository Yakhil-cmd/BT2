### Title
Unsanitized `ENV` fallback in command interpolation leaks host process secrets to unprivileged pull-request authors - ([File: lib/shipit/environment_variables.rb])

### Summary
Shipit builds an explicit, whitelisted environment hash (`Shipit.env`, `machine.environment`, `deploy.variables`, etc.) that is meant to be the only set of variables a `shipit.yml`-authored command can reference. However, when that command line is interpolated for execution, any `$VARNAME` token that is *not* found in the whitelisted hash silently falls back to the real Ruby process environment of the Shipit application host. This breaks the binding "environment key permitted == environment key resolvable at spawn time," and is reachable by an unprivileged pull-request author through the merge-queue/commit-checks feature, which executes commands sourced from the PR's own (attacker-controlled) `shipit.yml` using the app's global `Shipit.env`, not a merge-time-approved, per-stack sanitized env.

### Finding Description
`EnvironmentVariables#permit` enforces a whitelist model: any key not declared in `deploy_variables`/`rollback_variables` raises `NotPermitted`. [1](#0-0) 

But the *interpolation* path used to substitute `$VAR` tokens inside shell command strings does not go through `permit` at all. It fetches from the supplied `@env` hash, and if the key is missing there, falls back to the literal, unrestricted `ENV` of the Shipit Rails process: [2](#0-1) 

This is exercised by `Command#interpolated_arguments`/`interpolate_environment_variables`, which is called right before every command is spawned via `PTY.spawn`: [3](#0-2) [4](#0-3) 

The behavior is explicitly confirmed by the test suite: an env var never declared to the `Command` still resolves from the real process `ENV` at interpolation time. [5](#0-4) 

The reachable path for an unprivileged attacker is `EphemeralCommitChecks`, used by the merge-queue/commit-checks feature to run `dependencies` and `review.checks` steps declared in the **commit's own `shipit.yml`** (i.e., the pull request author's tree, checked out into a temporary working directory) with the global `Shipit.env` as the "permitted" environment: [6](#0-5) [7](#0-6) 

Because this feature runs checks against commits proposed via pull request (no merge, no repository write access needed — only the ability to open a PR against the tracked repository), the `review.checks`/`dependencies` command lines are fully attacker-controlled. An attacker can put `echo $SOME_HOST_SECRET` in their fork's `shipit.yml`; since `SOME_HOST_SECRET` is not part of the deliberately-scoped `Shipit.env` hash, `EnvironmentVariables#interpolate` resolves it from the real Shipit application process environment (e.g., database credentials, cloud credentials, or other secrets injected into the host's env for the Rails app) and prints it into the check output, which is captured and surfaced back to the (unprivileged) PR author via `EphemeralCommitChecks#output`.

### Impact Explanation
This breaks the trust boundary between "environment variables the operator explicitly permitted to be visible to deploy scripts" and "environment variables actually resolvable when a script is spawned." An unprivileged contributor who can open a pull request can exfiltrate secrets that live in the Shipit host process's environment but were never intended to be exposed through `shipit.yml`-declared whitelists (`deploy.variables`, `machine.environment`). Depending on what the operator's deployment stores in process `ENV` (database URLs, cloud provider credentials, etc.), this can escalate to credential exfiltration, satisfying the Critical-impact bar for "exfiltration of ... secret" credentials.

### Likelihood Explanation
Likelihood is high for any Shipit deployment using the commit-checks/merge-queue feature (`review.checks`/`dependencies` steps) on a repository that accepts external pull requests, since the exploit requires nothing more than authoring a `shipit.yml` in one's own fork/branch and opening a PR — no Shipit session, API token, or repository write access is needed.

### Recommendation
`EnvironmentVariables#interpolate` should never fall back to the real process `ENV`; it should only resolve variables that are present in the explicitly-permitted hash (i.e., the same set enforced by `#permit`), and should render anything else as empty/undefined, consistent with how the whitelist is enforced elsewhere. Additionally, `EphemeralCommitChecks` should run PR-provided commands with a strictly scoped, per-check environment (not the global `Shipit.env`) so that command interpolation can never observe secrets that are not explicitly designated as script parameters.

### Proof of Concept
1. Attacker forks the tracked repository and opens a pull request adding to their `shipit.yml`:
```yml
review:
  checks:
    - echo "leak:$SOME_HOST_SECRET_ENV_VAR"
```
2. Shipit's merge-queue/commit-checks flow calls `PerformCommitChecksJob` → `EphemeralCommitChecks#run`, which builds the `echo` command with `env: Shipit.env`. [6](#0-5) 
3. `Command#interpolated_arguments` interpolates `$SOME_HOST_SECRET_ENV_VAR`; since it's absent from `Shipit.env`, `EnvironmentVariables#interpolate` fetches it from the real process `ENV`. [2](#0-1) 
4. The command's stdout (containing the secret value) is captured into `EphemeralCommitChecks#output`, which is exposed back to the PR author through the commit-checks UI/API, completing the exfiltration.

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

**File:** lib/shipit/command.rb (L81-95)
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
```

**File:** test/unit/command_test.rb (L29-36)
```ruby
    test "#interpolate_environment_variables fallback to ENV" do
      previous = ENV['SHIPIT_TEST']
      ENV['SHIPIT_TEST'] = 'quux'
      command = Command.new('cap $SHIPIT_TEST deploy', env: { 'ENVIRONMENT' => 'production' }, chdir: '.')
      assert_equal([%(cap quux deploy)], command.interpolated_arguments)
    ensure
      ENV['SHIPIT_TEST'] = previous
    end
```

**File:** app/models/shipit/ephemeral_commit_checks.rb (L14-21)
```ruby
    def run
      self.status = 'running'
      commands = StackCommands.new(stack)
      commands.with_temporary_working_directory(commit:) do |directory|
        deploy_spec = DeploySpec::FileSystem.new(directory, stack)
        capture_all(build_commands(deploy_spec.dependencies_steps, chdir: directory))
        capture_all(build_commands(deploy_spec.review_checks, chdir: directory))
      end
```

**File:** app/models/shipit/ephemeral_commit_checks.rb (L49-51)
```ruby
    def build_commands(commands, chdir:)
      commands.map { |c| Command.new(c, env: Shipit.env, chdir:) }
    end
```
