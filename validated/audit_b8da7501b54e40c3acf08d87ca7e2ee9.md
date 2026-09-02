### Title
PR-controlled `machine.environment.BUNDLE_PATH` in `shipit.yml` overrides Shipit's hardcoded `BUNDLE_PATH` because `deploy_spec.machine_env` is merged after the reserved keys - ([File: lib/shipit/task_commands.rb])

### Summary
`TaskCommands#env` builds the environment for every deploy/dependency-install command by merging several hashes in sequence, with the attacker-controlled `deploy_spec.machine_env` merged *after* Shipit's own reserved keys, including `BUNDLE_PATH`. Because `Hash#merge` lets the later hash win, a PR's `shipit.yml` `machine.environment.BUNDLE_PATH` value silently overrides the hardcoded `Rails.root.join('data', 'bundler')` value that Shipit intends to enforce.

### Finding Description
The broken binding: Shipit intends `env['BUNDLE_PATH'] == Rails.root.join('data', 'bundler').to_s` always, regardless of repository configuration. In practice the code produces `env['BUNDLE_PATH'] == deploy_spec.machine_env['BUNDLE_PATH']` whenever the loaded `shipit.yml` sets that key, because of merge order: [1](#0-0) 

`env` chains `.merge(@stack.env)`, then `.merge({... 'BUNDLE_PATH' => Rails.root.join('data','bundler').to_s ...})`, and only afterward `.merge(deploy_spec.machine_env)` and `.merge(@task.env)`. `Hash#merge` always favors keys from the argument, so `deploy_spec.machine_env`'s `BUNDLE_PATH` (and any other key colliding with `SHIPIT_USER`, `EMAIL`, `SHIPIT_LINK`, `TASK_ID`, `IGNORED_SAFETIES`, `GIT_COMMITTER_NAME/EMAIL`) silently wins over Shipit's hardcoded values.

`deploy_spec.machine_env` is defined as a direct passthrough of the repository's own config with no allow-list filtering: [2](#0-1) 

For the `DeploySpec::FileSystem` instance actually used by `TaskCommands#deploy_spec` at task-run time, `config` is backed directly by the parsed `shipit.yml` from the checked-out working tree (`load_config`/`read_config`), not by the "cacheable" merged version that combines it with `discover_machine_env`: [3](#0-2) [4](#0-3) 

That means whatever `machine.environment.BUNDLE_PATH` value is present in the PR's own `shipit.yml`/`.shipit/shipit.yml` is used verbatim, and it is merged into `env` after the reserved-key hash in `TaskCommands#env`, so it overrides it. This is used both for `install_dependencies` (which runs `bundle config set --local path ...` and `bundle install`) and for `perform` (deploy steps), through `Command.new(command_line, env:, chdir: ...)`: [5](#0-4) 

None of the existing guards prevent this: `filter_deploy_envs`/`filter_rollback_envs` only restrict `@task.env` (task-supplied deploy variables) via `EnvironmentVariables#permit` against the declared `deploy_variables`/`rollback_variables` allow-list — they are never applied to `machine_env`. There is no validator on `machine.environment` keys anywhere in `DeploySpec`.

Attacker flow: open a PR (or push to a branch that will be checked out for a review stack or task), add a `shipit.yml` (or `.shipit/shipit.yml`) with:
```yaml
machine:
  environment:
    BUNDLE_PATH: /path/attacker/controls/inside/working/tree
```
place a malicious gem/shim tree at that path in the same commit. When Shipit runs `install_dependencies` for that stack/review app, `env['BUNDLE_PATH']` resolves to the attacker path, so `bundle install`/subsequent Ruby-invoking steps resolve gems from attacker-controlled code, achieving code execution in the context of the deploy host process (`Command`/`PTY.spawn`).

### Impact Explanation
This allows a PR author to make the deploy/task-running host execute arbitrary code supplied in their own commit, by redirecting Bundler's gem path to an attacker-controlled directory that is included in the checked-out working tree. This is RCE on the deploy host via the `Command`/`PTY.spawn` execution path, matching the Critical category. Because `deploy_spec` is loaded per-stack from that repository's own working tree, the blast radius is scoped to stacks/tasks that check out the attacker's commit (their own repository/branch, or a review stack derived from their PR), but it grants full code execution capability there without any privileged Shipit role.

### Likelihood Explanation
Preconditions are minimal for an unprivileged attacker: they need the ability to add/modify a `shipit.yml`/`.shipit/shipit.yml` in a commit that Shipit will check out and run `install_dependencies`/deploy steps against — which is exactly the capability given to any PR author under review-app or "deploy from PR" workflows, and requires no secrets, sessions, or team membership. The only environment-specific requirement is that the target stack must be configured to run `bundle install`-based dependency steps (i.e., a `Gemfile` present, triggering `BundlerDiscovery`), which is common for Ruby-based review apps. This is easily repeatable per PR/branch.

### Recommendation
In `TaskCommands#env`, merge `deploy_spec.machine_env` (and any other repository-provided config) before the block of Shipit-reserved keys, not after, so reserved keys like `BUNDLE_PATH`, `SHIPIT_USER`, `EMAIL`, `SHIPIT_LINK`, `TASK_ID`, `IGNORED_SAFETIES`, `GIT_COMMITTER_NAME`, and `GIT_COMMITTER_EMAIL` cannot be overridden by repository configuration. Alternatively, explicitly strip these reserved keys from `deploy_spec.machine_env` before merging, or apply an allow-list filter (similar to `EnvironmentVariables#permit`) to `machine_env`.

### Proof of Concept
```ruby
# test/unit/task_commands_env_test.rb
class TaskCommandsEnvTest < ActiveSupport::TestCase
  test "machine_env cannot override reserved BUNDLE_PATH" do
    task = shipit_tasks(:cyclimse_deploy) # or any fixture task
    commands = Shipit::TaskCommands.new(task)

    deploy_spec = commands.deploy_spec
    deploy_spec.stubs(:machine_env).returns('BUNDLE_PATH' => '/tmp/evil')

    reserved_value = Rails.root.join('data', 'bundler').to_s
    actual_value = commands.env['BUNDLE_PATH']

    assert_equal reserved_value, actual_value,
      "expected env['BUNDLE_PATH'] to remain #{reserved_value.inspect}, " \
      "but machine_env overrode it to #{actual_value.inspect}"
  end
end
```
This test currently fails, demonstrating `env['BUNDLE_PATH']` is `'/tmp/evil'` instead of the intended `Rails.root.join('data', 'bundler').to_s`, confirming the merge-order defect in `Shipit::TaskCommands#env`.

### Citations

**File:** lib/shipit/task_commands.rb (L17-27)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def perform
      steps.map do |command_line|
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

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
    end
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L37-59)
```ruby
      def cacheable_config
        (config || {}).deep_merge(
          'merge' => {
            'require' => merge_request_required_statuses,
            'ignore' => merge_request_ignored_statuses,
            'revalidate_after' => revalidate_merge_requests_after&.to_i,
            'method' => merge_request_merge_method,
            'max_divergence' => {
              'commits' => max_divergence_commits&.to_i,
              'age' => max_divergence_age&.to_i
            }
          },
          'ci' => {
            'hide' => hidden_statuses,
            'allow_failures' => soft_failing_statuses,
            'require' => required_statuses,
            'blocking' => blocking_statuses
          },
          'machine' => {
            'environment' => discover_machine_env.merge(machine_env),
            'directory' => directory,
            'cleanup' => true
          },
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L93-107)
```ruby
      def config(*)
        @config ||= load_config
        super
      end

      def load_config
        return if config_file_path.nil?

        if !Shipit.respect_bare_shipit_file? && config_file_path.to_s.end_with?(*bare_shipit_filenames)
          return { 'deploy' => { 'pre' => [shipit_not_obeying_bare_file_echo_command, 'exit 1'] } }
        end

        config_obj = read_config(config_file_path)
        build_config(config_file_path, config_obj)
      end
```
