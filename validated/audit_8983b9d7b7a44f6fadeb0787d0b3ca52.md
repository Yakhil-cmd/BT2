### Title
Fork-controlled `machine.environment.PYTHONSTARTUP` in `shipit.yml` overrides host env for every review-stack task, including `dependencies.override` - ([File: app/models/shipit/deploy_spec.rb])

### Summary
When `provisioning_behavior=allow_all`, Shipit automatically provisions a `ReviewStack` for any opened PR, including from forks, and clones the PR's own head branch to run its commands. `DeploySpec#machine_env` returns `config('machine', 'environment')` verbatim from that fork-controlled `shipit.yml`, and `TaskCommands#env` merges it unfiltered into the environment that `Command#unbundled_env` passes to `PTY.spawn` for every step, including the `dependencies.override` commands.

### Finding Description
The broken binding is: the env hash passed to `PTY.spawn` for the `dependencies.override` step should equal `BASE_ENV` plus only trusted/expected keys (`SHIPIT_USER`, `TASK_ID`, task-defined variables, etc.), but instead it equals `BASE_ENV.merge(@env.stringify_keys)` where `@env` includes `deploy_spec.machine_env`, which is attacker-controlled content from `config('machine','environment')` [1](#0-0) .

Path: `OpenedHandler#provision?` auto-approves provisioning for any opened PR when `repository.provisioning_behavior_allow_all?` is true [2](#0-1) . The resulting `ReviewStack` clones the PR head branch and `DeploySpec::FileSystem` reads `shipit.yml` from that checked-out fork branch [3](#0-2) . `TaskCommands#install_dependencies` builds the `dependencies.override` commands with `env:` computed by `TaskCommands#env`, which merges `deploy_spec.machine_env` verbatim, unfiltered, into the hash [4](#0-3) . `Command#unbundled_env` then merges `@env.stringify_keys` on top of the interpreter's real, unbundled environment, and that hash is passed directly to `PTY.spawn` in `Command#start` [5](#0-4) . Unlike `deploy_variables`/`rollback_variables`, which are filtered through `EnvironmentVariables#permit` (`filter_deploy_envs`/`filter_rollback_envs`) before merging into task envs [6](#0-5) , `machine_env` has no such filtering or allowlist — it is returned and merged as-is.

An attacker forks the target repo, adds a `shipit.yml` with:
```yaml
machine:
  environment:
    PYTHONSTARTUP: "path/to/malicious.py"
```
and opens a PR. Because `provisioning_behavior=allow_all`, `OpenedHandler` immediately provisions a `ReviewStack` for the fork PR with no maintainer approval. When Shipit's `install_dependencies`/deploy machinery runs the `dependencies.override` step (or any task) for that stack, `PYTHONSTARTUP` reaches the spawned process's environment via the described merge chain. If any step in the pipeline (dependency install script, discovery-generated commands, etc.) invokes a `python` interpreter, `PYTHONSTARTUP` causes that file to be executed at interpreter start, on the Shipit deploy host, under whatever privileges the Shipit worker has.

None of the existing guards intercept this: `verify_signature`/`GitHubApp#verify_webhook_signature` only validate that the webhook came from GitHub, not the content of the fork's `shipit.yml`; `ExplicitParameters` validates webhook shape, not deploy-spec content; model validations on `Repository`/`Stack` do not constrain `machine.environment` keys; `EnvironmentVariables#permit` is applied to `deploy_variables`/`rollback_variables` only, not to `machine_env`.

### Impact Explanation
This is Critical: a fork PR can achieve command/interpreter-controlled code execution on the Shipit deploy host by setting arbitrary environment variables (not limited to `PYTHONSTARTUP` — any similarly interpreter-honored variable, e.g. `RUBYOPT`, `NODE_OPTIONS`, `BASH_ENV`, `PERL5OPT`, etc.) via `machine.environment`, provided any tool in the `dependencies.override`/deploy pipeline invokes that interpreter. This is repeatable per PR and applies to every repository that has enabled `review_stacks_enabled` with `provisioning_behavior=allow_all`; the blast radius is scoped to stacks/tasks running on the shared deploy host for that repository (and potentially other tenants if the host is shared and other guardrails such as containerization are absent).

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled: true` and `provisioning_behavior: allow_all` (an explicit opt-in repository setting), and the pipeline must actually invoke an interpreter that honors the injected variable (e.g., `python`, present when the `dependencies.override`/discovery steps call it, or auto-discovered via `PypiDiscovery`). Attacker cost is minimal: fork the repo, add a `shipit.yml`, open a PR — no privileges, tokens, or secrets required. This is fully repeatable against any repo configured this way.

### Recommendation
Do not merge `machine.environment` from an untrusted `shipit.yml` (fork branch) verbatim into the process environment. At minimum: (1) strip/deny known interpreter-hijacking variable names (`PYTHONSTARTUP`, `RUBYOPT`, `NODE_OPTIONS`, `BASH_ENV`, `PERL5OPT`, `LD_PRELOAD`, etc.) from `machine_env`; (2) apply the same `EnvironmentVariables#permit`/allowlist mechanism used for `deploy_variables`/`rollback_variables` to `machine_env`; (3) for review stacks specifically, disallow `machine.environment` entirely or require maintainer review before honoring fork-provided `shipit.yml` machine environment settings.

### Proof of Concept
```ruby
test "dependencies.override step inherits PYTHONSTARTUP from fork-controlled machine.environment" do
  stack = shipit_stacks(:review_stack) # or a built ReviewStack fixture with provisioning_behavior allow_all
  write_fork_shipit_yml(stack, <<~YAML)
    machine:
      environment:
        PYTHONSTARTUP: "malicious.py"
    dependencies:
      override:
        - "echo installing"
  YAML

  task = create_task(stack)
  commands = Shipit::TaskCommands.new(task)
  step = commands.install_dependencies.first

  assert_equal "malicious.py", step.env["PYTHONSTARTUP"]
  # And verify it survives into the spawn-time env:
  assert_equal "malicious.py", step.unbundled_env["PYTHONSTARTUP"]
end
```
This asserts both sides of the binding — the value read from `deploy_spec.machine_env` and the value present in the hash `Command#unbundled_env` builds for `PTY.spawn` — are equal to the attacker-supplied value, confirming the fork-controlled key reaches process spawn for the `dependencies.override` phase.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-70)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L16-21)
```ruby
      def initialize(app_dir, stack)
        @app_dir = Pathname(app_dir)
        @env = stack.environment
        @stack = stack
        super(nil)
      end
```

**File:** lib/shipit/task_commands.rb (L17-48)
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

    def steps
      @task.definition.steps
    end

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
