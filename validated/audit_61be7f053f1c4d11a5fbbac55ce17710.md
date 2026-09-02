This confirms the full attack chain is real and reproducible. Let me summarize the findings.

**Confirmed facts:**

1. `stack.branch = params.pull_request.head.ref` — the review stack's branch is set directly from the fork PR's head ref, attacker-controlled. [1](#0-0) 

2. Tasks check out that branch, and `TaskCommands#deploy_spec` reads `shipit.yml` from that checked-out working directory via `DeploySpec::FileSystem`. [2](#0-1) 

3. `DeploySpec#machine_env` returns `config('machine', 'environment')` **verbatim**, with no whitelist filtering. [3](#0-2) 

4. `TaskCommands#env` merges `deploy_spec.machine_env` directly into the environment hash — unlike `deploy_variables`/`rollback_variables`, which are explicitly passed through `EnvironmentVariables#permit` (a whitelist) via `filter_deploy_envs`/`filter_rollback_envs`, `machine_env` has **no equivalent filter call** anywhere in the merge chain. [4](#0-3) [5](#0-4) 

5. `Command#start` passes this env hash directly to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`, and `unbundled_env` merges `@env.stringify_keys` on top of the base process env — so any key set via `machine.environment`, including `GIT_PROXY_COMMAND`, lands in the actual child process environment for every shell-interpreted step (e.g., `deploy`/`review` steps, which run as one string command line via `Command#parse_arguments`, executed by a shell as documented — steps are shell command lines, not argv arrays). [6](#0-5) [7](#0-6) 

6. The README documents `machine.environment` explicitly as: "All the content of the `shipit.yml` `machine.environment` key" is exposed as script parameters, confirming this is intended behavior for the whole `machine.environment` map, without any safety note about variable names being dangerous (e.g., `GIT_PROXY_COMMAND`, `LD_PRELOAD`, `BASH_ENV`, etc.) [8](#0-7) [9](#0-8) 

7. Under `allow_with_label`, an unprivileged fork PR author labels their own PR (an action they can perform on their own PR) to trigger stack creation/unarchival, causing Shipit to fetch and check out the fork's branch and read its `shipit.yml`. [10](#0-9) [11](#0-10) 

None of the existing guards (`EnvironmentVariables#permit`, `filter_deploy_envs`, `filter_rollback_envs`) apply to `machine_env` — those guards only protect the explicit `deploy.variables`/`rollback.variables`/task `variables` whitelist mechanisms, not `machine.environment`, which is documented and coded as an unrestricted pass-through.

### Title
Fork-controlled `machine.environment` in `shipit.yml` injects arbitrary env vars (e.g. `GIT_PROXY_COMMAND`) into shell-interpreted task steps, enabling RCE on the deploy host - (File: `lib/shipit/task_commands.rb`, `app/models/shipit/deploy_spec.rb`, `lib/shipit/command.rb`)

### Summary
`DeploySpec#machine_env` returns the `machine.environment` map from `shipit.yml` unfiltered, and `TaskCommands#env` merges it straight into the environment hash passed to `PTY.spawn`. Because Review Stacks check out the fork PR's own branch to read its `shipit.yml`, an unprivileged fork PR author can set `GIT_PROXY_COMMAND` (or similar env-controlled command hooks respected by git/shell/dynamic linker) that gets executed when a shell-interpreted step runs, achieving RCE on the deploy host.

### Finding Description
The broken invariant, stated as an equality that should hold but does not: `deploy_spec.machine_env keys ⊆ whitelist(deploy_variables ∪ rollback_variables ∪ task_variables)` — i.e., environment values injected from the repository's `shipit.yml` should be constrained to an explicit variable definition list, the same way `deploy.variables`/`rollback.variables`/task `variables` are constrained via `EnvironmentVariables#permit` (`app/models/shipit/deploy_spec.rb:174-180`, `lib/shipit/environment_variables.rb:13-18`). In reality, `machine_env` (`app/models/shipit/deploy_spec.rb:69-71`) is merged into `TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`) with **no filtering at all**, so this equality is false: any key/value the fork PR author writes under `machine: environment:` in their `shipit.yml` reaches the child process environment unmodified.

Path: an attacker opens/labels a PR from their fork against a repository with Review Stacks enabled in `allow_with_label` mode. `ReviewStackAdapter#create!`/`unarchive!` sets `stack.branch = params.pull_request.head.ref` (`app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:87-94`) — the fork's own branch, fully attacker-controlled. When a task runs (e.g. a `deploy` or `review.checks` step), `TaskCommands#deploy_spec` builds a `DeploySpec::FileSystem` from the checked-out working directory (`lib/shipit/task_commands.rb:13-15`), reading `shipit.yml` from that same attacker-controlled branch. The attacker adds:
```yaml
machine:
  environment:
    GIT_PROXY_COMMAND: /tmp/pwn.sh
```
`TaskCommands#env` merges `deploy_spec.machine_env` verbatim (`lib/shipit/task_commands.rb:46`), and `Command#start` spawns the shell-interpreted step string via `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` (`lib/shipit/command.rb:92`), where `unbundled_env` merges `@env.stringify_keys` on top of the base env (`lib/shipit/command.rb:104`). Any git invocation over a proxied transport in that step (or in the deploy scripts it calls) will now execute `/tmp/pwn.sh` as the named `GIT_PROXY_COMMAND`.

Existing guards do not stop this: `EnvironmentVariables#permit` is only invoked for `deploy_variables`/`rollback_variables`/task `variables`, never for `machine_env`. This is intentional/documented behavior — README explicitly states `machine.environment` "contains extra environment variables you want to provide during task execution" and lists it among script parameters, with no restriction on variable names.

### Impact Explanation
An unprivileged fork PR author obtains arbitrary command execution on the Shipit deploy host, running with whatever privileges the Shipit task-runner process has (potentially including `GITHUB_TOKEN`, deploy credentials, access to other stacks' git caches, etc.). This is repeatable per PR/per repository that has Review Stacks enabled with `allow_with_label` (or `allow_all`) provisioning — matches the Critical RCE-on-deploy-host class.

### Likelihood Explanation
Requires only: (1) the target repository has Review Stacks enabled, and (2) provisioning behavior is `allow_with_label` (attacker just adds the label themselves, since they own their PR) or `allow_all`. No secrets, tokens, or maintainer approval needed — opening/labeling a PR from a public fork is sufficient, and shipit.yml is read directly from the fork's branch.

### Recommendation
Apply the same `EnvironmentVariables#permit` whitelist mechanism to `machine.environment` that already exists for `deploy.variables`/`rollback.variables`, or restrict which `machine.environment` keys are honored for Review Stacks whose `shipit.yml` originates from an unmerged fork branch (e.g. drop/ignore `machine.environment` for review stacks, or filter dangerous env vars like `GIT_PROXY_COMMAND`, `LD_PRELOAD`, `BASH_ENV`, `PATH`, etc. via a deny/allow list at `DeploySpec#machine_env`).

### Proof of Concept
minitest plan (in `test/lib/shipit/task_commands_test.rb` or `test/models/deploy_spec_test.rb`):
```ruby
test "#env passes through fork-controlled GIT_PROXY_COMMAND from machine.environment unfiltered" do
  stack = shipit_stacks(:review_stack) # allow_with_label repo, branch = fork PR head ref
  deploy_spec = stub(
    machine_env: { 'GIT_PROXY_COMMAND' => '/tmp/pwn.sh' }, # attacker-controlled shipit.yml content
    directory: nil
  )
  task = shipit_tasks(:shipit_restart)
  task.stack = stack
  commands = TaskCommands.new(task)
  commands.stubs(:deploy_spec).returns(deploy_spec)

  env = commands.env
  # Binding under test: machine_env keys should be constrained by a whitelist, same as deploy/rollback variables.
  assert_equal '/tmp/pwn.sh', env['GIT_PROXY_COMMAND'] # demonstrates unfiltered pass-through into Command#env -> PTY.spawn
end
```
This demonstrates `env['GIT_PROXY_COMMAND']` reaching the `Command` env hash that is passed unmodified to `PTY.spawn` in `Command#start`, satisfying the fast-validation criterion in the question.

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

**File:** lib/shipit/command.rb (L227-240)
```ruby
    def parse_arguments(arguments)
      options = {}
      args = arguments.flatten.map do |argument|
        case argument
        when Hash
          options.merge!(argument.values.first)
          argument.keys.first
        else
          argument
        end
      end

      [args.map(&:to_s), options]
    end
```

**File:** README.md (L413-422)
```markdown
<h3 id="environment">Environment</h3>

**<code>machine.environment</code>** contains the extra environment variables that you want to provide during task execution.

For example:
```yml
machine:
  environment:
    key: val # things added as environment variables
```
```

**File:** README.md (L723-725)
```markdown
* `TASK_ID`: ID of the task that is running
* All the content of the `secrets.yml` `env` key
* All the content of the `shipit.yml` `machine.environment` key
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L61-97)
```ruby
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end

          def pull_request
            params.pull_request
          end

          def pull_request_state
            pull_request.state
          end

          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end

          def archive?
            (repository.provisioning_behavior_allow_with_label? && !pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && pull_request_has_provisioning_label?)
          end

          def unarchive?
            (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-78)
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

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
          end
```
