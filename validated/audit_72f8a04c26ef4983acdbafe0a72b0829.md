Confirmed. The trace is fully verified and matches the reported issue exactly.

### Title
Undeclared task/deploy step variables fall back to Shipit's own process `ENV`, leaking host secrets into task output - ([File: lib/shipit/environment_variables.rb])

### Summary
`EnvironmentVariables#interpolate` resolves `$VAR` references in command steps via `@env.fetch(variable) { ENV[variable] }`, silently falling back to the Shipit server process's own environment for any variable name used in a step but not declared in the task's `variables:` list (and thus never present as a key in the task's stored `env` hash). Since `EnvironmentVariables#permit`/`sanitize_env_vars` only rejects keys that *are present* in the caller-supplied env hash and are *not* whitelisted, an omitted-but-undeclared variable name never reaches that filter at all, and the interpolation-time fallback silently substitutes the Shipit process's own `ENV[variable]` into the shell command executed via `PTY.spawn`.

### Finding Description
The broken binding: the value substituted for `$BRANCH_NAME` in a step should equal a value the triggering party explicitly supplied (or `nil`/empty if undeclared), i.e. `task.env.fetch('BRANCH_NAME', nil) == interpolated_value`. Instead, when `BRANCH_NAME` is not declared in `variables:`, `task.env` never contains the key, and interpolation falls back to `ENV['BRANCH_NAME']` — Shipit's own process environment — so `interpolated_value == ENV['BRANCH_NAME']`, a value entirely outside the caller's or repository owner's control.

Code path:
- `Shipit::Api::TasksController#trigger` calls `stack.trigger_task(params[:task_name], current_user, env: params.env)` [1](#0-0) .
- `Stack#trigger_task` builds `env` from defaults and the request-supplied hash, then calls `definition.filter_envs(env)` before storing it on the `Task` record [2](#0-1) .
- `TaskDefinition#filter_envs` calls `EnvironmentVariables.with(env).permit(variables)` [3](#0-2) .
- `EnvironmentVariables#permit`/`sanitize_env_vars` only partitions keys that exist in the *supplied* `@env` hash against `variable_definitions.map(&:name)`; a variable name that is never a key of `@env` (because it was never declared, so never defaulted or requested) causes no rejection and is simply absent from the stored `env` [4](#0-3) [5](#0-4) .
- At execution time, `Command#interpolated_arguments` calls `interpolate_environment_variables`, which delegates to `EnvironmentVariables.with(env).interpolate(argument)` using the *stored task env* [6](#0-5) .
- `EnvironmentVariables#interpolate` does `Shellwords.escape(@env.fetch(variable) { ENV[variable] })` — when the key is absent from `@env`, it falls back to the Shipit host process's own `ENV` [7](#0-6) .
- The interpolated argument list is passed straight to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [8](#0-7) , and the process's stdout (including the leaked value) is captured and displayed on the task page.

Attacker's exact request: open a pull request modifying `shipit.yml` to add a task whose step string references `$SOME_ENV_VAR_NAME` (e.g., a name likely to collide with a real deployment secret exported in Shipit's own process environment, such as `$DATABASE_PASSWORD` or `$AWS_SECRET_ACCESS_KEY`) without declaring it under that task's `variables:`. Once merged and later triggered normally (by any authorized `ApiClient` or UI user who does not pass that key in `env`), the step silently echoes the Shipit server's own process environment variable of that name into the task log.

Why the existing test suite's guard (`EnvironmentVariables::NotPermitted`) doesn't help: that check (exercised by `test/unit/environment_variables_test.rb`) only fires when the caller's `env` hash *contains* a disallowed key; it never inspects which variable names are actually referenced inside step strings, so a name that's simply never supplied bypasses the whitelist entirely and reaches the `ENV[variable]` fallback in `interpolate`.

### Impact Explanation
Any value present in the Shipit host process's `ENV` under a name that a task step happens to reference (and that isn't declared as a task variable) is written verbatim into the task's captured stdout, visible to anyone who can view that task's page (any user with read access to the stack). If the deploy host process exports credentials such as `GITHUB_TOKEN`, database passwords, or other deploy-time secrets as environment variables (a common pattern for Rails/Shipit deployments), this becomes a direct exfiltration primitive of deploy-time secrets, matching the Critical category ("exfiltration of ... deploy-time secrets"). It's repeatable against any repository whose `shipit.yml` is merged with such a step, and the blast radius is bounded to whatever the Shipit process's environment exposes, but that commonly includes highly sensitive material shared with the host process.

### Likelihood Explanation
Requires: (1) a `shipit.yml` change containing an undeclared-variable step to be merged (an operator/maintainer action, stated as a precondition outside attacker control), and (2) a subsequent legitimate task trigger that omits that variable name from `env` (the common case, since nobody would normally think to supply a value for a name they never declared). No special repository configuration, secrets, or privileged access is needed by the attacker beyond crafting the PR content; the mechanism itself requires zero attacker-side execution once merged and triggered — it fires automatically on every trigger that doesn't happen to collide-override the name.

### Recommendation
Remove the `ENV[variable]` fallback in `EnvironmentVariables#interpolate` (`lib/shipit/environment_variables.rb`); undeclared/unsupplied variables should interpolate to an empty string (or raise) rather than reading from the Shipit process's own environment. If certain host-level variables must be intentionally exposed, they should be explicitly whitelisted per-task via `variables:`/`default:` rather than via an implicit global fallback.

### Proof of Concept
In a minitest unit test (e.g. added to `test/unit/environment_variables_test.rb` or `test/unit/command_test.rb`):
```ruby
test 'interpolate leaks process ENV for undeclared variable names' do
  previous = ENV['SHIPIT_SECRET_TEST']
  ENV['SHIPIT_SECRET_TEST'] = 'leaked-secret'
  begin
    # task env hash never contains SHIPIT_SECRET_TEST because it was never
    # declared in `variables:` and never supplied by the caller
    task_env = {}
    result = Shipit::EnvironmentVariables.with(task_env).interpolate('echo $SHIPIT_SECRET_TEST')
    assert_equal 'echo leaked-secret', result
  ensure
    ENV['SHIPIT_SECRET_TEST'] = previous
  end
end
```
End-to-end equivalent: stub `TaskDefinition#filter_envs`/`Stack#trigger_task` with a task definition whose only step is `echo $SHIPIT_SECRET_TEST` and no `variables:` entry, call `stack.trigger_task(...)` with `env: {}`, run the resulting `Command`, and assert the captured output equals `'leaked-secret'` — demonstrating `task.env` never contains the key while the executed command still substitutes the host's `ENV` value.

### Citations

**File:** app/controllers/shipit/api/tasks_controller.rb (L20-21)
```ruby
      def trigger
        render_resource(stack.trigger_task(params[:task_name], current_user, env: params.env), status: :accepted)
```

**File:** app/models/shipit/stack.rb (L139-159)
```ruby
    def trigger_task(definition_id, user, env: nil, force: false)
      definition = find_task_definition(definition_id)
      env = env.to_h

      definition.variables_with_defaults.each do |variable|
        env[variable.name] ||= variable.default
      end

      commit = last_deployed_commit.presence || commits.first
      task = tasks.create(
        user_id: user.id,
        definition:,
        until_commit_id: commit.id,
        since_commit_id: commit.id,
        env: definition.filter_envs(env),
        allow_concurrency: definition.allow_concurrency? || force,
        ignored_safeties: force
      )
      task.enqueue
      task
    end
```

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
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

**File:** lib/shipit/command.rb (L51-83)
```ruby
    def interpolate_environment_variables(argument)
      return argument.map { |a| interpolate_environment_variables(a) } if argument.is_a?(Array)

      EnvironmentVariables.with(env).interpolate(argument)
    end

    def success?
      !code.nil? && code.zero?
    end

    def exit_message
      "#{self} #{termination_status}"
    end

    def run
      output = []
      stream do |out|
        output << out
      end
      output.join
    end

    def run!
      output = []
      stream! do |out|
        output << out
      end
      output.join
    end

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
