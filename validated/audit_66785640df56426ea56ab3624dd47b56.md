### Title
Arbitrary process-environment variable exfiltration via `EnvironmentVariables#interpolate` fallback to `ENV` - (File: lib/shipit/environment_variables.rb)

### Summary
`Shipit::EnvironmentVariables#interpolate` substitutes any `$VAR` token found in a shell command by first checking the task's sanitized env hash, and if the key is absent, falling back to the *Shipit host process's own* `ENV[VAR]`. Because task/deploy/rollback steps are defined in the repository's own `shipit.yml` (which an unprivileged contributor controls via a pull request), a step can reference any process-level secret name (e.g. `$GITHUB_TOKEN`) that was never declared in the task's `variables:` whitelist, and have its value echoed into the task log.

### Finding Description
The broken binding, stated as an equality that should hold but does not:
`value interpolated into the shell command for token $VAR == a value present in @task.env/@stack.env that an authorized user explicitly supplied for this task's declared variables list`.

In practice:
```ruby
# lib/shipit/environment_variables.rb
def interpolate(argument)
  return argument unless @env
  argument.gsub(/(\$\w+)/) do |variable|
    variable.sub!('$', '')
    Shellwords.escape(@env.fetch(variable) { ENV[variable] })
  end
end
``` [1](#0-0) 

`@env.fetch(variable) { ENV[variable] }` silently falls through to the Shipit *host process's* environment (`ENV`) whenever the referenced name is not a key in the command's own env hash. This fallback is unconditional and independent of the `variables:` whitelist mechanism (`TaskDefinition#filter_envs` / `EnvironmentVariables#permit`), which only sanitizes *user-supplied inputs going into* `@task.env`, and never gates what `interpolate` is allowed to read [2](#0-1) .

Call path: `TaskCommands#perform` builds `Command.new(command_line, env:, chdir:)` where `command_line` comes verbatim from `@task.definition.steps`, i.e., directly from the repository's `shipit.yml` [3](#0-2) . `Command#start` calls `interpolated_arguments`, which calls `interpolate_environment_variables`, which delegates to `EnvironmentVariables.with(env).interpolate` [4](#0-3) [5](#0-4) . The resulting interpolated string is passed straight to `PTY.spawn`, and stdout is streamed into the visible task log by the execution strategy.

Existing guards do not touch this: `require_permission!`/webhook signature checks gate who can trigger a deploy, and `filter_envs`/`permit` gate what values a caller can inject as task inputs — but neither restricts what `interpolate` may read from the process's real `ENV` when resolving `$VAR` tokens found in the step text itself, which originates from the repository's own `shipit.yml`, a file fully controlled by any contributor who can open a PR.

### Impact Explanation
Any authorized trigger (continuous deployment or an operator manually running a deploy/rollback/task) against a commit whose `shipit.yml` contains a step like `echo $GITHUB_TOKEN`, `$AWS_SECRET_ACCESS_KEY`, or any other process-level secret name, causes that secret's value to be echoed into the task's log output, which is visible to anyone who can view the stack's task pages. This is exfiltration of the Shipit host's own credentials (matches the "Critical: exfiltration of GITHUB_TOKEN / deploy-time secrets" category) and is repeatable for any repository the attacker can get merged/deployed into, and for any secret name present in the host process's `ENV` (not limited to `GITHUB_TOKEN`).

### Likelihood Explanation
Preconditions are modest: the attacker needs a `shipit.yml` change to land in a commit that later gets deployed/run as a task (either via continuous deployment, or by a repository maintainer/operator triggering a deploy/rollback on that commit) — no Shipit session, API token, or GitHub secret is required to *author* the change. Cost is low (a single PR); repeatability is high since it works for any variable name and doesn't depend on race conditions or timing.

### Recommendation
Remove the `ENV[variable]` fallback in `EnvironmentVariables#interpolate`; only allow interpolation of variables explicitly present in the command's already-whitelisted env hash, and raise/leave the token un-substituted (or blank) for anything else, so step-referenced variables are bound only to values the task/stack explicitly declared and provided.

### Proof of Concept
```ruby
# test/unit/command_test.rb (new test)
test 'interpolate does not leak host process ENV into command output' do
  ENV['GITHUB_TOKEN'] = 'super-secret-token'
  command = Shipit::Command.new('echo $GITHUB_TOKEN', env: {}, chdir: '.')
  output = command.run
  assert_no_match(/super-secret-token/, output,
    "expected $GITHUB_TOKEN to only resolve from the command's own env, not the host ENV")
ensure
  ENV.delete('GITHUB_TOKEN')
end
```
Before the fix: `output` contains `super-secret-token` (equality `interpolated byte == host ENV['GITHUB_TOKEN']` holds, which it should not). After removing the `ENV` fallback: the two sides diverge as intended (assertion passes).

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

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
    end
```

**File:** lib/shipit/task_commands.rb (L23-27)
```ruby
    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
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
