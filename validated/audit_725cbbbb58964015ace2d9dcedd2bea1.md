### Title
`TaskCommands#env` merges attacker-controlled `@task.env` after Shipit-reserved keys, letting `shipit.yml` `deploy.variables` named `SHIPIT_USER`/`TASK_ID`/`EMAIL` override the core-set values - (File: `lib/shipit/task_commands.rb`)

### Summary
`DeploySpec#deploy_variables` accepts any string as a variable `name` from `shipit.yml`, with no reserved-word blocklist, and `EnvironmentVariables#permit` (used by `Stack#filter_deploy_envs`) only checks that the key is present in that whitelist. Because `TaskCommands#env` merges `@task.env` (the deploy's stored, filtered env) *after* the block that hardcodes `SHIPIT_USER`, `EMAIL`, and `TASK_ID`, a `shipit.yml` that declares a variable named `SHIPIT_USER` (or `TASK_ID`/`EMAIL`) whose value ends up in `task.env` will silently overwrite the core-supplied value that reaches `Command#env` and ultimately `PTY.spawn`.

### Finding Description
The broken binding is: `Command#env['SHIPIT_USER'] == "#{triggering_user.login} (...) via Shipit"` for every deploy, regardless of `shipit.yml` content. Tracing the code:

- `DeploySpec#deploy_variables` builds `VariableDefinition` objects straight from `config('deploy','variables')` with no name filtering: [1](#0-0) .
- `Stack#build_deploy` filters any caller-supplied `env` hash through `filter_deploy_envs`, which is `EnvironmentVariables.with(env).permit(deploy_variables)` — this only checks membership in `deploy_variables.map(&:name)`, not against a reserved-key list: [2](#0-1)  and [3](#0-2)  and [4](#0-3) .
- If `shipit.yml` declares `deploy.variables: [{name: 'SHIPIT_USER', default: 'attacker'}]`, then `SHIPIT_USER` becomes a permitted key. Any env hash reaching `build_deploy` that carries `SHIPIT_USER` — either the automatic `default_deploy_env` used for continuous delivery (`Stack#trigger_continuous_delivery`, passing `cached_deploy_spec.default_deploy_env`, i.e. `deploy_variables.map { |v| [v.name, v.default] }.to_h`) or an operator-submitted deploy form whose params are permitted via `params.require(:deploy).permit(:until_commit_id, env: @stack.deploy_variables.map(&:name))` — will pass the filter and be persisted as `task.env['SHIPIT_USER'] = 'attacker'`: [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) .
- `TaskCommands#env` sets the reserved keys, then merges `deploy_spec.machine_env`, and **then** merges `@task.env` last — so `@task.env['SHIPIT_USER']` wins over the hardcoded value: [9](#0-8) .
- This merged hash flows unmodified into `Command.new(..., env:)` and then `Command#env`/`unbundled_env`, which is passed to `PTY.spawn`: [10](#0-9) [11](#0-10) .

None of the listed guards stop this: `filter_deploy_envs`/`EnvironmentVariables#permit` is a whitelist by *name*, not a reserved-key blacklist, and `deploy_params` in `DeploysController` derives its own permitted list from the same attacker-controlled `@stack.deploy_variables`, so the controller-level "permit" is circular and offers no protection.

### Impact Explanation
A repository/PR author who controls `shipit.yml` can cause `SHIPIT_USER` (and identically `TASK_ID`/`EMAIL`) values passed to deploy scripts to be forged. Deploy scripts that use `SHIPIT_USER` for auditing or authorization decisions would see an attacker-chosen identity instead of the real triggering user. This is repeatable for every deploy/continuous-delivery run against that stack while the malicious `shipit.yml` is in effect, and is confined to the stack/repository whose spec is compromised (it does not cross tenants by itself, since `deploy_variables` is scoped to `cached_deploy_spec` for that stack) — matching a Critical-adjacent but stack-scoped authenticity break of an operator-facing audit value, since it is "a command running with forged identity input" but not itself an unauthorized deploy/RCE/exfiltration on its own.

### Likelihood Explanation
Preconditions: the attacker needs the ability to get a `shipit.yml`/`.shipit/*.yml` with a `deploy.variables` entry named `SHIPIT_USER` (or `TASK_ID`/`EMAIL`) merged/loaded for a stack whose deploy spec is sourced from attacker-influenced content (e.g., a review stack tracking the attacker's own PR branch, as implied by the question's precondition "review stack running a deploy triggered by any user"). No secrets or elevated Shipit roles are required beyond what's needed to get the spec loaded — this matches the stated unprivileged-PR-author threat model. Triggering continuous delivery (`Stack#trigger_continuous_delivery`) requires no extra action from any privileged party beyond a normal deploy occurring; an operator-initiated deploy through `DeploysController#create` with default/blank env fields would also pick up the attacker's default if the deploy form pre-populates from `deploy_variables`.

### Recommendation
Reserve `SHIPIT_USER`, `TASK_ID`, `EMAIL` (and other core-only keys like `SHIPIT`, `SHIPIT_LINK`, `ENVIRONMENT`, `BRANCH`, `GITHUB_REPO_NAME`, `GITHUB_REPO_OWNER`, `GIT_COMMITTER_NAME/EMAIL`) at the `DeploySpec#deploy_variables`/`rollback_variables` parsing layer, rejecting or ignoring any `VariableDefinition` whose `name` collides with a reserved key. Additionally, in `TaskCommands#env`, merge the reserved-key hash **last** (after `@task.env` and `deploy_spec.machine_env`) so it cannot be shadowed regardless of upstream filtering gaps.

### Proof of Concept
```ruby
# test/lib/shipit/task_commands_reserved_key_test.rb
require 'test_helper'

class TaskCommandsReservedKeyOverrideTest < ActiveSupport::TestCase
  test "attacker-declared SHIPIT_USER deploy variable cannot override the real triggering user" do
    stack = shipit_stacks(:shipit)
    real_user = shipit_users(:walrus) # the REAL triggering user

    # Simulate shipit.yml: deploy.variables: [{name: 'SHIPIT_USER', default: 'attacker'}]
    stack.cached_deploy_spec_content = {
      'deploy' => {
        'variables' => [{ 'name' => 'SHIPIT_USER', 'default' => 'attacker' }]
      }
    }.to_json
    stack.save!

    # default_deploy_env, as used by Stack#trigger_continuous_delivery / run_deploy_in_foreground
    env = stack.cached_deploy_spec.default_deploy_env
    assert_equal({ 'SHIPIT_USER' => 'attacker' }, env)

    task = shipit_tasks(:shipit_restart)
    task.stack = stack
    task.user = real_user
    task.env = stack.filter_deploy_envs(env) # simulates build_deploy's filtering
    assert_equal({ 'SHIPIT_USER' => 'attacker' }, task.env) # filter does NOT block reserved key

    command_env = Shipit::TaskCommands.new(task).env

    # BROKEN BINDING: attacker default wins over the real user
    # This assertion currently PASSES, proving the vulnerability:
    assert_equal 'attacker', command_env['SHIPIT_USER']

    # Desired/fixed behavior (currently FAILS):
    # assert_equal "#{real_user.login} (#{real_user.name}) via Shipit", command_env['SHIPIT_USER']
  end
end
```

### Citations

**File:** app/models/shipit/deploy_spec.rb (L120-126)
```ruby
    def deploy_variables
      Array.wrap(config('deploy', 'variables')).map(&VariableDefinition.method(:new))
    end

    def default_deploy_env
      deploy_variables.map { |v| [v.name, v.default] }.to_h
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

**File:** app/models/shipit/stack.rb (L161-172)
```ruby
    def build_deploy(until_commit, user, env: nil, force: false, allow_concurrency: force)
      since_commit = last_deployed_commit.presence || commits.first
      deploys.build(
        user_id: user.id,
        until_commit:,
        since_commit:,
        env: filter_deploy_envs(env.to_h),
        allow_concurrency:,
        ignored_safeties: force || !until_commit.deployable?,
        max_retries: retries_on_deploy
      )
    end
```

**File:** app/models/shipit/stack.rb (L210-228)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
```

**File:** app/controllers/shipit/deploys_controller.rb (L66-68)
```ruby
    def deploy_params
      @deploy_params ||= params.require(:deploy).permit(:until_commit_id, env: @stack.deploy_variables.map(&:name))
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

**File:** lib/shipit/command.rb (L31-34)
```ruby
    def initialize(*args, chdir:, default_timeout: Shipit.default_inactivity_timeout, env: {})
      @args, options = parse_arguments(args)
      @timeout = parse_timeout(options['timeout'] || options[:timeout]) || default_timeout
      @env = env.transform_values { |v| v&.to_s }
```

**File:** lib/shipit/command.rb (L92-104)
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
```
