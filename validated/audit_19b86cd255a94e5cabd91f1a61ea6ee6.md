Confirmed: this is a real vulnerability path.

### Title
Unfiltered `machine.environment` in fork PR's `shipit.yml` reaches `PTY.spawn`, allowing `RUBYOPT` injection (RCE) - ([File: app/models/shipit/deploy_spec.rb, lib/shipit/task_commands.rb, lib/shipit/command.rb])

### Summary
`ReviewStack.branch` is set directly from `params.pull_request.head.ref` [1](#0-0) , meaning the checked-out branch (and therefore its `shipit.yml`) is fully attacker-controlled by whoever opens the PR. `DeploySpec#machine_env` returns `config('machine', 'environment')` with no whitelist filtering [2](#0-1) , unlike `deploy`/`rollback` variables which are explicitly sanitized via `EnvironmentVariables#permit` through `filter_deploy_envs`/`filter_rollback_envs` [3](#0-2) . `TaskCommands#env` merges this unfiltered hash directly into the environment passed to every `Command` [4](#0-3) , and `Command#unbundled_env`/`start` pass it verbatim to `PTY.spawn` [5](#0-4) .

### Finding Description
The broken invariant: `deploy_spec.machine_env == EnvironmentVariables.with(config('machine','environment')).permit(whitelist)` is expected to hold (as it does for `deploy_variables`/`rollback_variables`), but instead `machine_env` returns the raw config hash unfiltered [2](#0-1) .

Path: an unprivileged user opens a PR from their fork. `OpenedHandler` creates a `ReviewStack` whose `branch` is the fork's head ref, taken verbatim from the webhook payload [1](#0-0) . When Shipit deploys/provisions this review stack, `TaskCommands#deploy_spec` builds a `DeploySpec::FileSystem` from the checked-out working directory of that branch [6](#0-5) , i.e., it reads the fork's own `shipit.yml`. The attacker adds:
```yaml
machine:
  environment:
    RUBYOPT: "-r/tmp/evil"
```
`TaskCommands#env` merges `deploy_spec.machine_env` directly into the process environment for every step's `Command.new` call, with no call to `permit`/whitelist [4](#0-3) . `Command#unbundled_env` merges `@env` on top of `BASE_ENV` and hands it to `PTY.spawn` [7](#0-6) [8](#0-7) . Any subsequent `ruby`/`rake`/`bundle` invocation in the dependency-install or deploy steps then loads `/tmp/evil` at interpreter startup, executing attacker code on the Shipit host.

This differs from the `deploy`/`rollback` variable paths, which are explicitly filtered through `EnvironmentVariables#permit` against a repository-maintainer-defined whitelist (`deploy_variables`/`rollback_variables`) before being accepted [9](#0-8) [3](#0-2) . No equivalent whitelist exists for `machine.environment`, and no other guard (`verify_signature`, `require_permission!`, `EnvironmentVariables#permit`) is applied to it.

### Impact Explanation
This is Critical — arbitrary code execution on the Shipit deploy host, triggered purely by opening/pushing to a PR from an attacker-owned fork, no Shipit credentials required. Since deploy/provisioning steps typically invoke `ruby`, `bundle`, or `rake`, `RUBYOPT=-r/tmp/evil` (or any other dangerous variable such as `LD_PRELOAD`, `BUNDLE_GEMFILE`, `GIT_SSH_COMMAND`, etc.) executes attacker code with the privileges of the Shipit worker process, which typically holds `GITHUB_TOKEN` and other deploy-time secrets — enabling secret exfiltration and lateral movement to other stacks/repositories. This is repeatable against every repository that permits review-stack creation for fork PRs.

### Likelihood Explanation
Low cost, high feasibility: the attacker only needs to open a PR from a fork containing a `shipit.yml` with a `machine.environment` block, on a repository that has review-stack provisioning enabled for PRs (a common, documented Shipit feature for CI review apps). No approval, label, or maintainer action is required for the malicious `shipit.yml` to be read and merged into the spawn environment, since `DeploySpec::FileSystem` reads directly from the checked-out fork branch.

### Recommendation
Apply the same whitelist mechanism used for `deploy_variables`/`rollback_variables` to `machine.environment`: introduce a maintainer-controlled whitelist (e.g., `machine_variables` defined in the base repo's own trusted config, not the fork branch) and filter `machine_env` through `EnvironmentVariables#permit` before merging into `TaskCommands#env`. Alternatively, disallow `machine.environment` entirely from being sourced from an untrusted/fork branch for review stacks, or explicitly block known-dangerous variable names (`RUBYOPT`, `LD_PRELOAD`, `BUNDLE_*`, `GIT_SSH_COMMAND`, `PATH`, etc.).

### Proof of Concept
```ruby
# test/unit/task_commands_test.rb (or similar)
test "fork-controlled machine.environment RUBYOPT reaches Command#unbundled_env verbatim" do
  spec_config = { 'machine' => { 'environment' => { 'RUBYOPT' => '-r/tmp/evil' } } }
  deploy_spec = Shipit::DeploySpec.new(spec_config)

  # binding under test: machine_env should be filtered but isn't
  assert_equal({ 'RUBYOPT' => '-r/tmp/evil' }, deploy_spec.machine_env)

  command = Shipit::Command.new('ruby', '-e', '1', env: deploy_spec.machine_env, chdir: Dir.tmpdir)
  spawned_env = command.unbundled_env

  assert_equal '-r/tmp/evil', spawned_env['RUBYOPT']
end
```
This demonstrates `deploy_spec.machine_env` propagates unfiltered into the exact hash passed to `PTY.spawn` via `Command#unbundled_env`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L87-94)
```ruby
          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
    end
```

**File:** app/models/shipit/deploy_spec.rb (L120-122)
```ruby
    def deploy_variables
      Array.wrap(config('deploy', 'variables')).map(&VariableDefinition.method(:new))
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

**File:** lib/shipit/task_commands.rb (L13-15)
```ruby
    def deploy_spec
      @deploy_spec ||= DeploySpec::FileSystem.new(@task.working_directory, @stack)
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

**File:** lib/shipit/command.rb (L92-105)
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
    end
```
