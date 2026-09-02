### Title
Unfiltered `shipit.yml` `machine.environment` (e.g. `GIT_PROXY_COMMAND`) reaches `PTY.spawn` for fork-controlled review-stack tasks - (File: lib/shipit/task_commands.rb)

### Summary
`TaskCommands#env` merges `deploy_spec.machine_env` — the raw `machine.environment` hash read straight from the checked-out `shipit.yml` — into the process environment with no allowlist, unlike `deploy_variables`/`task variables` which are always passed through `EnvironmentVariables#permit`. For a `prevent_with_label` review stack, the checked-out commit is the fork PR's own HEAD, so the PR author fully controls `shipit.yml`, and thus can set arbitrary env vars such as `GIT_PROXY_COMMAND` that `git` (invoked by any subsequent shell-interpreted step) will execute as a command on the Shipit host.

### Finding Description
The broken binding: the code assumes `env reaching PTY.spawn == allowlisted(shipit.yml env)`, but in reality `env reaching PTY.spawn ⊇ raw(shipit.yml machine.environment)` for the `machine.environment` key specifically.

- `DeploySpec::FileSystem#machine_env` (`app/models/shipit/deploy_spec.rb:69-71`) returns `config('machine', 'environment') || {}` — i.e., whatever the `shipit.yml` in the checked-out commit specifies under `machine.environment`, unfiltered.
- `TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`) does `.merge(deploy_spec.machine_env)` directly into the env hash used for every `Command.new(..., env:, ...)` call for `install_dependencies` and `perform` (deploy/rollback/task steps).
- Contrast this with `deploy_variables`/`rollback_variables`/task `variables`, which are always passed through `EnvironmentVariables#permit` (`lib/shipit/environment_variables.rb:13-18`, `filter_deploy_envs`/`filter_rollback_envs`/`TaskDefinition#filter_envs`) — an explicit allowlist mechanism that raises `NotPermitted` for unlisted keys. `machine_env` has no such gate.
- `Command#env` (`lib/shipit/command.rb:34`) just stringifies values, and `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) merges `BASE_ENV` + `PATH` + `@env.stringify_keys` with no key restriction.
- `Command#start` (`lib/shipit/command.rb:85-101`) calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`. Any step defined as a single string (e.g., `deploy: override: - "some_command"`) is executed through `/bin/sh -c` semantics (Ruby's `Kernel#spawn`/`PTY.spawn` treats a single string command as shell-interpreted).
- For a review stack in `prevent_with_label` mode, an unprivileged PR (that simply doesn't carry the "prevent" label) is auto-provisioned by `OpenedHandler`/`ReviewStackAdapter` (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`). Its `Task`/`Deploy` checks out the PR author's own fork branch (`TaskCommands#checkout` checks out `commit.sha`, which for review stacks is a commit on the PR's own head ref). That means the attacker's `shipit.yml`, including `machine.environment.GIT_PROXY_COMMAND`, is the exact file used to build `deploy_spec`.
- `GIT_PROXY_COMMAND` is a real git environment variable: git executes the named program to establish the transport connection for any `git://` or similar remote (or effectively any invocation of `git` in the step) — attacker-controlled command execution as soon as any step invokes `git` with a matching transport (or the attacker can specify a step that invokes `git ls-remote git://x` itself since they control the deploy/task steps' contents too, but more importantly they control an env var read by `git` in *any* step, including the framework's own `git clone`/`git checkout` operations in `StackCommands`/`TaskCommands`, which run as part of every task).
- No existing guard intercepts this: `verify_signature`/webhook auth only gate whether the webhook is accepted, not what the fork's own file contains; `EnvironmentVariables#permit` is simply never invoked on `machine_env`; there is no `Repository`/`Stack` validation on `shipit.yml` content since it is fetched from the repo's own git history, which for a review stack is the fork.

### Impact Explanation
Executing an attacker-named `GIT_PROXY_COMMAND` value causes arbitrary command execution on the Shipit deploy host in the context whichever git invocation happens during the task (clone/checkout are done automatically by `TaskCommands#clone`/`#checkout`, both of which run `git` and would inherit this env var). This is Critical — Remote Code Execution on the Shipit deploy host, matching the "Critical - RCE on the deploy host via `Command`/`PTY.spawn`" impact category. Because it's mediated purely by the fork's own `shipit.yml`, the attack is fully repeatable per PR/push, and any repository owner enabling review stacks with `prevent_with_label` (an opt-out model, not opt-in) on a repo accepting external forks is exposed. The blast radius is the shared Shipit host process user, potentially compromising all stacks/secrets accessible from that host, not just the attacker's own review stack.

### Likelihood Explanation
Preconditions: the target `Repository` must have `review_stacks_enabled` with `provisioning_behavior: prevent_with_label` (an opt-out configuration explicitly documented as accepting all PRs by default unless labeled). Attacker cost is minimal — open a fork PR without the "prevent" label, include a `shipit.yml` with `machine: {environment: {GIT_PROXY_COMMAND: "<attacker command>"}}`. No secrets, tokens, or privileged roles are required; the attacker only needs the ability to open a PR and control their own fork's file contents, which is granted to any GitHub user against a public repo with review stacks enabled in this mode. This is fully repeatable and requires no race conditions or timing.

### Recommendation
Filter `machine.environment` (and any other free-form `shipit.yml`-sourced env content) through an explicit allowlist or a denylist of dangerous variable names (`GIT_PROXY_COMMAND`, `GIT_SSH`, `GIT_SSH_COMMAND`, `LD_PRELOAD`, `BASH_ENV`, `PATH`, etc.) before merging into `TaskCommands#env`. At minimum, apply `EnvironmentVariables#permit` semantics (or a hard-coded blocklist of interpreter/tool-hijacking variable names) to `deploy_spec.machine_env` the same way `deploy_variables`/task `variables` are sanitized, and ensure this sanitization happens even for the framework's own internal `git` invocations (`clone`, `checkout`) that occur before user-defined steps run.

### Proof of Concept
minitest plan (`test/unit/task_commands_test.rb` or similar):
1. Build a `ReviewStack` fixture with `provisioning_behavior: prevent_with_label`, whose associated `PullRequest`/commit checks out a working directory containing a `shipit.yml` with:
   ```yaml
   machine:
     environment:
       GIT_PROXY_COMMAND: "/tmp/attacker_payload"
   deploy:
     override:
       - "git ls-remote origin"
   ```
2. Instantiate `TaskCommands.new(task)` for that stack/commit and call `env`.
3. Assert equality: `env['GIT_PROXY_COMMAND'] == '/tmp/attacker_payload'` (the binding under test — no value should flow from an unauthenticated allowlist-less source into the spawn environment).
4. Assert that `Command.new(task_commands.steps.first, env: task_commands.env, chdir: ...).unbundled_env['GIT_PROXY_COMMAND']` equals the attacker-supplied value, proving it reaches the `PTY.spawn` env argument.
5. Contrast with a `deploy_variables`-only test showing `DANGEROUS_VARIABLE` is rejected via `EnvironmentVariables::NotPermitted` when passed through the deploy `env` params path, demonstrating the inconsistency between the two code paths. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
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
