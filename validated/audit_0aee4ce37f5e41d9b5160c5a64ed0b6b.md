### Title
Unfiltered PR-label injection into task environment allows `BUNDLE_GEMFILE`/`BUNDLE_PATH` override in `bundle install` - (File: lib/shipit/task_commands.rb)

### Summary
`ReviewStack#env` converts every PR label into an env var (`LABEL_NAME` => `"true"`), and `TaskCommands#env` merges this `@stack.env` directly into the env passed to `Command`/`PTY.spawn`, without ever passing it through `EnvironmentVariables#permit` / `VariableDefinition` whitelisting the way task-triggered custom env is. `BUNDLE_PATH` happens to get re-overridden later in the same merge chain, but `BUNDLE_GEMFILE` is never re-set, so a label named `BUNDLE_GEMFILE` survives into the `bundle install` invocation for that review app's tasks.

### Finding Description
The claimed broken binding: `keys(Command#unbundled_env.@env) ∩ keys(Bundler-honored env vars) == ∅`, guaranteed by `deploy_spec`'s `VariableDefinition`/`EnvironmentVariables#permit` filtering. This is false for label-derived env vars.

- `ReviewStack#env` uppercases every PR label and sets it to `"true"` in the env hash, unconditionally: [1](#0-0) 
- `TaskCommands#env` merges `@stack.env` (which is `ReviewStack#env` for review-app tasks) directly, with no call to `EnvironmentVariables#permit`/`filter_deploy_envs`/`filter_task_envs` anywhere in the chain: [2](#0-1) 
- Compare this to the *only* place label/whitelist filtering exists: `Stack#build_deploy`/`Stack#trigger_task`, which filter the **user-submitted** deploy/task env via `filter_deploy_envs`/`definition.filter_envs` (`EnvironmentVariables#permit`): [3](#0-2)  — `@stack.env` (the labels) never goes through this path.
- `EnvironmentVariables#permit` is the only place `NotPermitted` is raised for un-whitelisted keys, and it operates on the deploy/task env, not on `stack.env`: [4](#0-3) 
- In the `TaskCommands#env` merge order, `BUNDLE_PATH` set by labels is overwritten twice (once by the literal `'BUNDLE_PATH' => Rails.root.join('data','bundler').to_s` and again by `deploy_spec.machine_env` via `discover_machine_env`), but no code overwrites `BUNDLE_GEMFILE`: [2](#0-1) [5](#0-4) 
- This merged env is passed unfiltered into `Command.new(..., env:, chdir: steps_directory)` for `install_dependencies`, which ultimately reaches `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`: [6](#0-5) [7](#0-6) 
- Existing tests confirm labels are intentionally exposed as env vars for review-stack tasks with no filtering: [8](#0-7) [9](#0-8) 

Attacker flow: attacker opens/owns a PR against a Shipit-tracked repository that uses Bundler, labels it `BUNDLE_GEMFILE`, and commits a file literally named `true` in the branch root containing Ruby/Gemfile-DSL code. When the review stack's `install_dependencies`/`perform` steps run `bundle install`/`bundle exec` with `chdir: steps_directory` (the checked-out PR branch), `BUNDLE_GEMFILE=true` in the environment causes Bundler to resolve the Gemfile as the relative path `./true`, which is attacker-controlled content, executing arbitrary Ruby on the deploy host.

None of the existing guards (`EnvironmentVariables#permit`, `filter_deploy_envs`, `filter_task_envs`) apply to this code path because they only sanitize user/API-submitted deploy/task `env:` params, not `Stack#env`/`ReviewStack#env`.

### Impact Explanation
Arbitrary Ruby code execution on the Shipit deploy host during `bundle install`/`bundle exec` for a review-app task, running with whatever privileges the Shipit worker process has (including access to `GITHUB_TOKEN`, other stacks' git caches, and the host filesystem) — this is Critical RCE via `Command`/`PTY.spawn`. Because it is triggered purely by adding a label to a PR plus committing a maliciously named file, it is repeatable on every push/label event for that stack, and could be used to pivot to other stacks/tenants if the shared host is not otherwise isolated.

### Likelihood Explanation
Requires: (1) the target repository to be Shipit-managed with review apps enabled and Bundler auto-detected (a real `Gemfile` present), (2) the attacker to be able to attach a label to their own PR, and (3) commit a file named `true` to their branch. Per the stated threat model, label-authorship on "their own PR" is granted as an in-scope attacker capability. In real-world GitHub permission models, adding labels typically requires write/triage access to the upstream repo, which narrows real-world applicability to insiders/collaborators rather than arbitrary forks — this caveat could not be fully verified against this engine's authorization code since label-setting is a GitHub-side permission, not enforced by Shipit. Given the stated ruleset, the precondition is accepted as attacker-reachable.

### Recommendation
Filter `Stack#env`/`ReviewStack#env` label-derived variables through an explicit allow-list before merging into `TaskCommands#env` (e.g., reuse `EnvironmentVariables#permit` with a dedicated `label_variables` allow-list configured in `shipit.yml`, or prefix label-derived vars, e.g. `LABEL_<NAME>`, so they can never collide with `BUNDLE_*`/other Bundler- or gem-loader-honored variable names). At minimum, explicitly strip/reset `BUNDLE_GEMFILE`, `BUNDLE_APP_CONFIG`, `RUBYOPT`, `GEM_HOME`, `GEM_PATH`, and similar loader-influencing keys after merging `@stack.env` in `TaskCommands#env`, mirroring what is already done for `BUNDLE_PATH`.

### Proof of Concept
Minitest under `test/lib/shipit/task_commands_test.rb`:
```ruby
test "#env does not leak BUNDLE_GEMFILE from a PR label" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["bundle_gemfile", "wip"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env

  # Binding under test: label-derived keys intersected with Bundler-honored
  # keys must be empty.
  bundler_honored_keys = %w[BUNDLE_GEMFILE BUNDLE_PATH BUNDLE_APP_CONFIG]
  refute bundler_honored_keys.include?("BUNDLE_GEMFILE") && env.key?("BUNDLE_GEMFILE"),
    "expected BUNDLE_GEMFILE to be stripped/filtered, got #{env['BUNDLE_GEMFILE'].inspect}"
  assert_nil env["BUNDLE_GEMFILE"]
end
```
This currently fails (`env["BUNDLE_GEMFILE"]` equals `"true"`), demonstrating the unfiltered pass-through described above.

### Citations

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
    end
```

**File:** lib/shipit/task_commands.rb (L17-21)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
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

**File:** app/models/shipit/stack.rb (L139-172)
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

**File:** lib/shipit/environment_variables.rb (L13-44)
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
```

**File:** app/models/shipit/deploy_spec/bundler_discovery.rb (L24-26)
```ruby
      def discover_machine_env
        super.merge('BUNDLE_PATH' => bundle_path.to_s)
      end
```

**File:** lib/shipit/command.rb (L85-105)
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
      @started = true
      self
    end

    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** test/lib/shipit/task_commands_test.rb (L1-17)
```ruby
# frozen_string_literal: true

require "test_helper"

class TaskCommandsTest < ActiveSupport::TestCase
  test "#env includes a ReviewStack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    stack.pull_request.labels = ["wip", "bug"]
    task = shipit_tasks(:shipit_restart)
    task.stack = stack

    env = Shipit::TaskCommands.new(task).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
  end
end
```

**File:** test/models/shipit/review_stack_test.rb (L59-65)
```ruby
    test "#env includes the stack's pull request labels" do
      stack = shipit_stacks(:review_stack)
      stack.pull_request.labels = ["wip", "bug"]

      assert_equal stack.env["WIP"], "true"
      assert_equal stack.env["BUG"], "true"
    end
```
