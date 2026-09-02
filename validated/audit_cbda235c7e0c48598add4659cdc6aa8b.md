### Title
Unfiltered `machine.environment`/`BUNDLE_GEMFILE` injection from an unprivileged fork PR's `shipit.yml` reaches `PTY.spawn` in review-stack tasks - (File: `lib/shipit/task_commands.rb`, `lib/shipit/command.rb`, `app/models/shipit/deploy_spec.rb`)

### Summary
`deploy_spec.machine_env`, which is populated straight from the checked-out commit's `shipit.yml` `machine.environment` key, is merged into the task environment with no key whitelist, unlike `deploy_variables`/`rollback_variables` which go through `EnvironmentVariables#permit`. `Command#unbundled_env` then merges that entire hash unfiltered into the child-process environment handed to `PTY.spawn`. On a repository with `provisioning_behavior=prevent_with_label`, an unprivileged fork PR is auto-provisioned into a `ReviewStack` by default (label absent), so the attacker's own `shipit.yml` is the one read and used to build the deploy environment.

### Finding Description
The broken binding: the invariant should be `keys(env reaching PTY.spawn) ⊆ whitelist(deploy_variables ∪ rollback_variables ∪ fixed task keys)`, but in practice `keys(env reaching PTY.spawn) ⊇ keys(deploy_spec.machine_env)` where `deploy_spec.machine_env` is taken verbatim from the PR branch's `shipit.yml`, with no whitelist applied.

- `DeploySpec#machine_env` simply reads `config('machine', 'environment') || {}` with no filtering: [1](#0-0) 
- Contrast with the deploy/rollback variable paths, which explicitly sanitize user input through a whitelist: [2](#0-1)  and the whitelist enforcement itself: [3](#0-2) 
- `TaskCommands#env` merges `deploy_spec.machine_env` directly into the task's environment hash, unfiltered, after the hardcoded task keys: [4](#0-3) 
- `Command#unbundled_env` merges `@env.stringify_keys` into `BASE_ENV` with no key restriction, and `Command#start` passes this hash directly to `PTY.spawn`: [5](#0-4) 
- `TaskCommands#deploy_spec` builds the spec from the actual checked-out working directory of the commit under deployment: [6](#0-5) , matching `Task#spec`: [7](#0-6) 
- Review stacks are created with `branch: params.pull_request.head.ref`, i.e., the fork PR's own head branch, taken straight from the webhook payload: [8](#0-7) 
- Under `prevent_with_label`, provisioning happens by default (opt-out) whenever the label is absent, so an ordinary attacker-authored PR is auto-provisioned without any maintainer action: [9](#0-8) 
- Bundler-related steps that will honor `BUNDLE_GEMFILE` (e.g. `bundle install`) are part of the standard discovered dependency steps executed via `Command`: [10](#0-9) 

Exploit flow: attacker opens a PR from their own fork against a repository with review stacks enabled and `provisioning_behavior=prevent_with_label`; the PR is auto-provisioned as a `ReviewStack` bound to the attacker's branch. The attacker's branch includes a `shipit.yml` with `machine.environment.BUNDLE_GEMFILE` pointing at a malicious `Gemfile` also included in that same branch, containing arbitrary Ruby code. When Shipit checks out that commit and runs dependency/deploy steps, `TaskCommands#env` folds `machine_env` (including `BUNDLE_GEMFILE`) unfiltered into the `Command` environment, which `Command#unbundled_env` forwards unchanged to `PTY.spawn`. Any subsequent `bundle` invocation on the deploy host loads and evaluates the attacker's Gemfile, executing arbitrary Ruby as the Shipit deploy-host process.

Existing guards do not stop this: `EnvironmentVariables#permit` is only invoked for `deploy_variables`/`rollback_variables` (user-supplied deploy-time form inputs), never for `machine_env`; there is no `Repository`/`Stack` validation restricting `shipit.yml` content; and `force_github_authentication`/webhook signature checks only gate whether the webhook is accepted, not what content the checked-out commit is allowed to declare in `machine.environment`.

### Impact Explanation
Arbitrary Ruby code execution on the Shipit deploy host, under whatever OS user runs Shipit's background job/worker process, triggered purely by opening a pull request from an untrusted fork. This is repeatable against any repository that has review stacks enabled with `prevent_with_label` (or `allow_all`) provisioning, requires no privileges beyond opening a PR, and gives the attacker a foothold on the host that runs deploys for potentially many other stacks/repositories sharing that host, `GITHUB_TOKEN`, and other deploy-time secrets. This matches the "Critical – RCE on the deploy host via `Command`/`PTY.spawn`" impact category.

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled = true` with `provisioning_behavior` set to `prevent_with_label` (or `allow_all`), which are legitimate/common configurations documented for review stacks. No secrets, tokens, or privileged roles are required — only the ability to open a pull request from a fork, which is the baseline capability assumed for any public repository accepting external contributions. The attacker cost is a single PR; the exploit is deterministic and fully repeatable against any repository configured this way.

### Recommendation
Apply the same `EnvironmentVariables#permit` whitelist mechanism (or an explicit, host-application-configured allowlist) to `deploy_spec.machine_env` before merging it into `TaskCommands#env`, and additionally hard-block known dangerous keys (`BUNDLE_GEMFILE`, `BUNDLE_PATH`, `RUBYOPT`, `LD_PRELOAD`, etc.) from ever being settable via repository-controlled `shipit.yml`, particularly for review stacks whose `shipit.yml` originates from an unprivileged fork branch.

### Proof of Concept
Minitest plan (`test/unit/task_commands_test.rb` or similar):
1. Build a `ReviewStack` with `provisioning_behavior: :prevent_with_label`.
2. Stub/construct a `DeploySpec::FileSystem`-equivalent (or a `DeploySpec.new` with `'machine' => { 'environment' => { 'BUNDLE_GEMFILE' => 'Gemfile.evil' } }`) representing the attacker's fork `shipit.yml`.
3. Build `TaskCommands` for a `Task`/`Deploy` on that stack, stub `deploy_spec` to return the malicious spec.
4. Assert: `commands.env['BUNDLE_GEMFILE'] == 'Gemfile.evil'` (equality that should NOT hold — the "before" expectation is `commands.env.key?('BUNDLE_GEMFILE') == false` given no whitelist entry for it).
5. Additionally, instantiate `Shipit::Command.new('bundle install', env: commands.env, chdir: dir)` and assert `command.unbundled_env['BUNDLE_GEMFILE'] == 'Gemfile.evil'`, confirming the value reaches the hash passed to `PTY.spawn`.

### Citations

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
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

**File:** app/models/shipit/task.rb (L222-224)
```ruby
    def spec
      @spec ||= DeploySpec::FileSystem.new(working_directory, stack)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/deploy_spec/bundler_discovery.rb (L12-37)
```ruby
      def discover_bundler
        bundle_install if bundler?
      end

      def bundle_exec(command)
        if bundler? && dependencies_steps.include?(remove_ruby_version_from_gemfile)
          "bundle exec #{command}"
        else
          command
        end
      end

      def discover_machine_env
        super.merge('BUNDLE_PATH' => bundle_path.to_s)
      end

      def bundle_install
        install_command = %(bundle install --jobs 4 --retry 2)
        [
          remove_ruby_version_from_gemfile,
          (bundle_config_frozen if frozen_mode?),
          bundle_config_path,
          bundle_without_groups,
          install_command
        ].compact
      end
```
