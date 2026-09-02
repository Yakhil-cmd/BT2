No vulnerability found for this question.

**Reasoning summary:**

The claimed exploit path is refuted by an existing guard. `Command#interpolate_environment_variables` delegates to `EnvironmentVariables#interpolate`, which explicitly shell-escapes every environment-variable *value* before substituting it into a step string: [1](#0-0) 

```ruby
def interpolate(argument)
  return argument unless @env

  argument.gsub(/(\$\w+)/) do |variable|
    variable.sub!('$', '')
    Shellwords.escape(@env.fetch(variable) { ENV[variable] })
  end
end
```

This is exactly the code path used before `PTY.spawn` in `Command#start`: [2](#0-1)  — `interpolated_arguments` calls `interpolate_environment_variables(@args)`, which calls `EnvironmentVariables.with(env).interpolate(argument)` for each argument string, and only then is the result handed to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`.

There is an existing regression test that directly demonstrates the mitigation holding for exactly the payload class described in the question (`$(...)`): [3](#0-2) 

```ruby
test '#interpolate_environment_variables escape the variable contents' do
  malicious_string = '$(echo pwnd)'
  command = Command.new('echo $FOO', env: { 'FOO' => malicious_string }, chdir: '.')
  assert_equal malicious_string, command.run.chomp
end
```

`machine.environment` entries from a fork-authored `shipit.yml` become environment-variable values consumed exactly this way — via `TaskCommands#env` merging `deploy_spec.machine_env` [4](#0-3)  and via `DeploySpec#machine_env` reading `config('machine', 'environment')` [5](#0-4) . Any `$VAR` reference to such a value inside a step string is escaped with `Shellwords.escape` before the shell ever sees it, so `;`, `$(...)`, backticks, and `&&` inside a `machine.environment` *value* are neutralized as literal characters, not executed.

Separately, the `deploy.override`/`dependencies.override` *step strings themselves* are not "attacker data injected into a trusted command" — they are the literal shell commands the repository owner (or PR author, for their own review stack) chose to write; treating them as executable is the documented, intended behavior of `shipit.yml`, not a boundary violation. Review stacks execute a PR's own `shipit.yml` in that PR's own review environment; the question does not demonstrate a path where one repository's or one tenant's secrets/commands are reachable by an unrelated attacker.

Since the specific mechanism alleged (metacharacters in `machine.environment` surviving into the shell command) is already blocked by `Shellwords.escape` in `EnvironmentVariables#interpolate`, and this is confirmed by an existing passing test, the invariant holds and no RCE is demonstrated.

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

**File:** lib/shipit/command.rb (L81-92)
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
```

**File:** test/unit/command_test.rb (L23-27)
```ruby
    test '#interpolate_environment_variables escape the variable contents' do
      malicious_string = '$(echo pwnd)'
      command = Command.new('echo $FOO', env: { 'FOO' => malicious_string }, chdir: '.')
      assert_equal malicious_string, command.run.chomp
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

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
    end
```
