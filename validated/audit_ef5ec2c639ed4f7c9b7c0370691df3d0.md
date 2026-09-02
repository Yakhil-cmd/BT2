### Title
Environment-variable interpolation falls back to the Shipit host's own process environment, bypassing the `shipit.yml`/task variable whitelist - ([File: lib/shipit/environment_variables.rb])

### Summary
`EnvironmentVariables#permit` is the gate that decides which env keys a deploy/task/rollback is allowed to carry, based on the `deploy.variables` / `rollback.variables` / task `variables` declared in `shipit.yml` [1](#0-0) [2](#0-1) . But the *interpolation* routine that actually substitutes `$VAR` tokens into the shell command line that gets `PTY.spawn`'d is a **separate** code path that is not bound by that same whitelist: when a variable referenced in a `shipit.yml` step string is missing from the permitted `@env` hash, it silently falls back to reading the Shipit server process's own `ENV`, i.e. the real environment of the Rails/worker process [3](#0-2) , and this is exactly what `Command#interpolated_arguments`/`Command#start` uses to build the argv passed to `PTY.spawn` [4](#0-3) [5](#0-4) .

### Finding Description
The binding that should hold is: **the set of environment keys a user is permitted to control/reference in a deploy/task/rollback == the set of environment keys that actually get substituted into the spawned command**. `Task#filter_envs`/`DeploySpec#filter_deploy_envs`/`filter_rollback_envs` are the enforcement points that raise `EnvironmentVariables::NotPermitted` if the caller tries to set a key that isn't declared in `shipit.yml`'s `variables:` list [2](#0-1) [6](#0-5) , and this is enforced at the API/UI boundary (`Api::DeploysController#create`, `Api::TasksController#trigger`) [7](#0-6) .

However, `shipit.yml` step commands (`deploy.steps`, `deploy.pre`, `deploy.post`, task `steps`, etc.) are free-text shell strings that can reference **any** `$VARNAME`, not just the declared, whitelisted ones. When such a command is executed, `Command#interpolate_environment_variables` delegates to `EnvironmentVariables.with(env).interpolate(argument)`, which for any variable not present in the (permitted) `env` hash falls back to `ENV[variable]` — the actual OS-level environment of the Shipit server/worker process [3](#0-2) . This fallback is confirmed and explicitly relied upon by the test suite (`"#interpolate_environment_variables fallback to ENV"`) [8](#0-7) .

The equality that is broken is:
`env keys permitted by shipit.yml’s declared variables` ≠ `env keys the spawned shell process can actually resolve via $VAR interpolation`

Any repository maintainer who can edit `shipit.yml` (the same trust level as anyone able to change deploy steps — not an API-token holder, not a privileged Shipit account, just someone who can land a `shipit.yml` change) can add a step such as:
```yaml
deploy:
  steps:
    - 'echo START-$GITHUB_TOKEN-END'
```
`GITHUB_TOKEN` is never one of the declared `deploy.variables`, so it is never present in the whitelisted `env` hash built by `TaskCommands#env`/`DeployCommands#env` — yet at execution time `interpolate` falls back to `ENV['GITHUB_TOKEN']`, which is the *Shipit host process's own* GitHub App/installation token used by `Shipit::GithubApp#token` and injected into `base_env` for git operations [9](#0-8) , and is also stored process-wide via `Command::BASE_ENV` (derived from `ENV`) [10](#0-9) . The command's stdout is captured verbatim into the task's output stream (`Task#write`) and is rendered to any user who can view the task/deploy log, without any additional permission check beyond `read:stack`.

### Impact Explanation
This allows exfiltration of secrets present in the Shipit application server's/worker's OS environment (potentially including `GITHUB_TOKEN`, database credentials, Redis URLs, or other secrets injected via `ENV` at deploy time) into a task's log output, which is visible to any user/API client with only `read:stack` permission on that stack. Depending on what the deployment host's `ENV` actually contains, this can reach the "exfiltration of `GITHUB_TOKEN`" critical-impact bucket named in the rules.

### Likelihood Explanation
Likelihood is limited by the fact that the attacker must be able to modify `shipit.yml` in the target repository (i.e., have commit/push access to the repo Shipit deploys), which is the same access level that lets someone define deploy/rollback/task steps in general. Given that access, the exploit is trivial and deterministic — no race condition or timing dependency — the fallback to `ENV[variable]` happens unconditionally whenever an unwhitelisted variable name is referenced in a step string.

### Recommendation
`EnvironmentVariables#interpolate` should not silently fall back to the host process's `ENV` for keys outside the permitted set. Interpolation should operate only over the already-filtered `env` hash (the same one produced by `filter_deploy_envs`/`filter_rollback_envs`/`Task#filter_envs`), and reference to an unknown/undeclared variable in a `shipit.yml` step should either be treated as empty string (as already happens for known-but-unset keys) or raise, but it must never resolve into the Shipit server process's own environment variables.

### Proof of Concept
1. In the target repository's `shipit.yml`, add a deploy step:
   ```yaml
   deploy:
     steps:
       - 'echo LEAK-$GITHUB_TOKEN-LEAK'
   ```
2. Trigger a deploy via the UI or `Api::DeploysController#create` for that stack, as any user with `deploy:stack` permission and no special privileges beyond that.
3. `DeployCommands#perform` builds `Command.new('echo LEAK-$GITHUB_TOKEN-LEAK', env: <declared-vars-only>, chdir: ...)`.
4. At `start`, `Command#interpolated_arguments` calls `EnvironmentVariables.with(env).interpolate(...)`; since `GITHUB_TOKEN` is not part of the deploy's permitted `env`, `@env.fetch('GITHUB_TOKEN') { ENV['GITHUB_TOKEN'] }` resolves to the Shipit process's `ENV['GITHUB_TOKEN']` [3](#0-2) .
5. The interpolated shell command executes with the real token substituted in, and its stdout (containing the token) is streamed into the task output, visible to any viewer of that task's log. [11](#0-10) [12](#0-11) [9](#0-8)

### Citations

**File:** lib/shipit/environment_variables.rb (L1-46)
```ruby
# frozen_string_literal: true

module Shipit
  class EnvironmentVariables
    NotPermitted = Class.new(StandardError)

    class << self
      def with(env)
        EnvironmentVariables.new(env)
      end
    end

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

    private

    def initialize(env)
      @env = env
    end

    def sanitize_env_vars(variable_definitions)
      allowed_variables = variable_definitions.map(&:name)

      allowed, disallowed = @env.partition { |k, _| allowed_variables.include?(k) }.map(&:to_h)

      error_message = "Variables #{disallowed.keys.to_sentence} have not been whitelisted"
      raise NotPermitted, error_message unless disallowed.empty?

      allowed
    end
  end
end
```

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```

**File:** lib/shipit/command.rb (L17-18)
```ruby
    unbundled_env = Bundler.respond_to?(:unbundled_env) ? Bundler.unbundled_env : Bundler.clean_env
    BASE_ENV = unbundled_env.merge((ENV.keys - unbundled_env.keys).map { |k| [k, nil] }.to_h)
```

**File:** lib/shipit/command.rb (L29-105)
```ruby
    attr_reader :out, :chdir, :env, :args, :pid, :timeout

    def initialize(*args, chdir:, default_timeout: Shipit.default_inactivity_timeout, env: {})
      @args, options = parse_arguments(args)
      @timeout = parse_timeout(options['timeout'] || options[:timeout]) || default_timeout
      @env = env.transform_values { |v| v&.to_s }
      @chdir = chdir.to_s
      @timed_out = false
    end

    def with_timeout(new_timeout)
      old_timeout = timeout
      @timeout = new_timeout
      yield
    ensure
      @timeout = old_timeout
    end

    def to_s
      @args.join(' ')
    end

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
      @started = true
      self
    end

    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
    end
```

**File:** test/controllers/api/deploys_controller_test.rb (L42-47)
```ruby
      test "#create refuses to trigger a new deploy with incorrect variables" do
        incorrect_env = { 'DANGEROUS_VARIABLE' => 1 }
        post :create, params: { stack_id: @stack.to_param, sha: @commit.sha, env: incorrect_env }
        assert_response :unprocessable_entity
        assert_json 'message', 'Variables DANGEROUS_VARIABLE have not been whitelisted'
      end
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
