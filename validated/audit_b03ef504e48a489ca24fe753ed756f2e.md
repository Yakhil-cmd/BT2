### Title
Command not-found/permission-denied errors leak env-interpolated secrets (e.g. `GITHUB_TOKEN`) into task output - (File: lib/shipit/command.rb)

### Summary
`Command#start` builds its `NotFound`/`Denied` exception messages from `Shellwords.split(interpolated_arguments.first).first`, which is the *post-interpolation* value of the command's first token, i.e. after `$VAR` substitution against the command's `env` hash. Because `TaskCommands#env`/`DeployCommands#env` (via `Commands#base_env`) inject the app-wide `GITHUB_TOKEN` into every deploy/task/rollback command's environment, a `shipit.yml` step that references `$GITHUB_TOKEN` (or any other secret env var) as the executable name will, on failure to exec, leak the raw secret value into the exception message, which `TaskExecutionStrategy::Default#run` writes verbatim to `@task.write` and thus into `chunk_output`, rendered by `DeploysController#show`.

### Finding Description
The broken binding: the exception message surfaced to `@task.write` should always be built from the **pre-interpolation** literal argument (`command.args.first`), never from `interpolated_arguments.first`. Instead: [1](#0-0) 

`start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, ...)`, where `interpolated_arguments` is produced by `interpolate_environment_variables`, which substitutes any `$VAR` pattern in the argument with `EnvironmentVariables.with(env).interpolate`, fetching the actual value from the command's `env` hash: [2](#0-1) 

`TaskCommands`/`DeployCommands`/`StackCommands` all derive their `env` from `Commands#base_env`, which unconditionally injects the live GitHub token: [3](#0-2) 

If a `shipit.yml` step's `command_line` (attacker-controlled content on the PR's own branch, which becomes the deploy/task/rollback/dependency step list read from `DeploySpec::FileSystem` for that stack) is something like:
```yml
deploy:
  override:
    - $GITHUB_TOKEN
```
then `interpolated_arguments.first` becomes the literal token value. Since that value is not a valid executable path, `PTY.spawn` raises `Errno::ENOENT`, and `Command#start` raises:
```ruby
raise NotFound, "#{Shellwords.split(interpolated_arguments.first).first}: command not found"
```
embedding the raw secret in the exception's `message`. `TaskExecutionStrategy::Default#run` rescues `Command::Error` and writes the message directly to the task log: [4](#0-3) 

That log is persisted via `Task#write` to Redis and served back through `chunk_output` in `DeploysController#show`: [5](#0-4) 

No component in the traced path (`EnvironmentVariables#interpolate`, `Command#start`, `TaskExecutionStrategy::Default#run`, `Task#write`) redacts or filters secret values before they reach the persisted task log; `EnvironmentVariables#permit` (the whitelist mechanism) is only used for user-supplied deploy `env` params in the controllers, not for the fixed `base_env` values like `GITHUB_TOKEN`, and is not applied to command error messages at all.

Attacker flow: an unprivileged GitHub user opens a PR (or pushes to a branch that becomes/updates a review stack) containing a `shipit.yml` step referencing `$GITHUB_TOKEN` (or any other secret merged into `Commands#base_env`/`TaskCommands#env`) as an invalid executable. When any authorized Shipit user later triggers a deploy, rollback, dependency install, or custom task on that stack (a normal, expected action, not requiring the attacker's own privilege), the step fails to exec and the raw secret is written into that task's output, readable by any Shipit user with view access to that stack's deploy page.

### Impact Explanation
This leaks `GITHUB_TOKEN` — the shared GitHub App/installation token used by Shipit to `git fetch`/`clone`/push across potentially many repositories in the org — into a task's persisted, publicly-viewable-to-authorized-users log. This is explicitly listed as a Critical impact ("exfiltration of `GITHUB_TOKEN`"). Because the token is not scoped to the single repository whose PR triggered the leak, an attacker who can get their crafted `shipit.yml` executed (via any legitimate deploy/task trigger by a maintainer) can obtain a credential usable against other repositories/stacks in the same GitHub organization — a cross-tenant blast radius. The attack is repeatable against any stack whose `shipit.yml` the attacker can influence (their own PR branch) and requires no compromise of Shipit secrets, sessions, or API tokens.

### Likelihood Explanation
Preconditions: the attacker must be able to get their `shipit.yml` content associated with a stack (fork/PR/branch, well within the stated unprivileged capabilities), and some authorized user must trigger a deploy/task/rollback against that content (an ordinary, expected workflow action, not an attacker action). Continuous-delivery on review stacks defaults to `continuous_deployment: false`, so typically a maintainer must click "Deploy"/"Run task" — this is a realistic and common occurrence for review stacks, custom tasks, or standard deploy pipelines where PR content controls `shipit.yml`. Attacker cost is minimal: a single crafted step referencing `$GITHUB_TOKEN` (or `$SHA`, `$SHIPIT_LINK`, etc. — though those aren't secret; the vulnerability generalizes to any secret in the merged env). The exploit is fully deterministic and repeatable.

### Recommendation
In `Command#start`, build the `NotFound`/`Denied` error messages from the pre-interpolation `@args.first` (or a sanitized/opaque description of the failing command) rather than `interpolated_arguments.first`, e.g.:
```ruby
rescue Errno::ENOENT
  raise NotFound, "#{Shellwords.split(@args.first).first}: command not found"
rescue Errno::EACCES
  raise Denied, "#{Shellwords.split(@args.first).first}: Permission denied"
```
More broadly, any code path that surfaces `interpolated_arguments`/`interpolated_environment_variables` output into logs, exceptions, or UI should redact known-secret env keys (`GITHUB_TOKEN`, etc.) before persisting to `Task#write`.

### Proof of Concept
```ruby
# test/unit/command_test.rb (new test)
test "start does not leak interpolated secret env values in NotFound message" do
  secret = 'ghp_supersecrettoken1234567890'
  command = Shipit::Command.new('$GITHUB_TOKEN', env: { 'GITHUB_TOKEN' => secret }, chdir: '.')

  error = assert_raises(Shipit::Command::NotFound) { command.start }

  refute_includes error.message, secret,
    "Command::NotFound message must not contain the interpolated secret value"
end
```
And an end-to-end variant asserting the secret never reaches `chunk_output`:
```ruby
# test/models/task_execution_strategy/default_test.rb (new test)
test "a failing command referencing a secret env var does not leak it into task output" do
  secret = 'ghp_supersecrettoken1234567890'
  Shipit::Commands.any_instance.stubs(:base_env).returns('GITHUB_TOKEN' => secret)
  # stub deploy_spec.dependencies_steps! (or deploy_steps!) to return ['$GITHUB_TOKEN']
  # run TaskExecutionStrategy::Default#run for the task
  assert_not_includes task.reload.chunk_output, secret
end
```
Both assertions currently fail against the given code (the secret is present in the message/output), demonstrating the vulnerability.

### Citations

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

**File:** app/models/shipit/task_execution_strategy/default.rb (L27-29)
```ruby
      rescue Command::Error => e
        @task.write("\n#{e.message}\n")
        @task.report_failure!(e)
```

**File:** app/controllers/shipit/deploys_controller.rb (L18-23)
```ruby
    def show
      respond_to do |format|
        format.html
        format.text { render(plain: @deploy.chunk_output) }
      end
    end
```
