### Title
Fork-controlled PR label names become unfiltered environment-variable keys (e.g. `BASH_ENV`) injected into `ruby`/`bundle` dependency-step commands - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` takes every pull-request label name, upper-cases it, and merges it as an environment-variable *key* (fixed value `"true"`) into the stack's env with no allowlist. This merged env flows unfiltered through `TaskCommands#env` into every `Command` built by `TaskCommands#install_dependencies`, which is then handed to `PTY.spawn` via `Command#unbundled_env`. Unlike the `deploy`/`rollback`/task custom-env paths, which are sanitized by `EnvironmentVariables#permit` against an explicit `variable_definitions` allowlist, this label-derived hash has no such filter, so an attacker who can label their own PR (which they can, since `allow_with_label`/`prevent_with_label` gate stack lifecycle on labels the PR author or repo controls) can inject reserved variable names such as `BASH_ENV`, `PATH`, `RUBYOPT`, `LD_PRELOAD`, etc. into the process environment of the dependency-installation commands.

### Finding Description
The broken binding: **the set of keys reaching `Command#unbundled_env`/`PTY.spawn` for a `ruby`/`bundle` dependency step should equal `Shipit.env ∪ shipit.yml machine_env ∪ task/deploy explicitly-permitted variables`**, but in practice it also equals `{label_name.upcase | label_name ∈ pull_request.labels}` with no allowlist check.

Code path:
- `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim from the webhook payload onto `PullRequest#labels`. [1](#0-0) 
- `ReviewStack#env` merges those raw names, upcased, as env keys with a fixed `"true"` value, with **no key allowlist**: [2](#0-1) 
- `TaskCommands#env` merges `@stack.env` (i.e. the label-derived hash) into the env used to build every dependency-step `Command`: [3](#0-2) 
- `Command#unbundled_env` merges `@env.stringify_keys` **last**, so it overrides even `PATH`, and that merged hash is passed directly to `PTY.spawn`: [4](#0-3) 

By contrast, the task-triggered custom env and deploy/rollback envs *are* explicitly allowlisted via `EnvironmentVariables#permit`, proving the engine has an established pattern for sanitizing attacker/user-supplied env keys that was not applied to the pull-request-label-derived env: [5](#0-4) [6](#0-5) 

Attack flow: an attacker opens a PR from a fork and applies (or has applied, since anyone controlling the PR/label API-equivalent webhook fields the repo already trusts under `allow_with_label` can do this) a label literally named `bash_env`. `LabeledHandler`/`LabelCapturingHandler` cause a `ReviewStack` to provision, and every task run against it (including the automatic dependency-install step) will have `BASH_ENV=true` in its process environment when the dependency command is executed.

Caveat on downstream impact: the label value is always the fixed string `"true"`, not attacker-chosen. For `BASH_ENV=true` to achieve code execution, the specific dependency-step command line would additionally need to be dispatched through a Bourne-compatible shell that actually honors `BASH_ENV` (i.e. `/bin/sh` is `bash`, which is not the default on common Linux distributions using `dash`), and a file literally named `true` would need to exist in the working directory that the shell resolves and sources. This second half of the exploit chain depends on host shell configuration and/or third-party gem/build-script internals outside this engine's own code, and is not proven purely from this codebase.

### Impact Explanation
What is demonstrably broken: arbitrary attacker-influenceable environment-variable **names** reach the process environment of privileged deploy-host commands (`bundle install`, `bundle config`, etc.) for a `ReviewStack`, bypassing the allowlist pattern (`EnvironmentVariables#permit`) that the engine already uses elsewhere for exactly this class of risk. This is repeatable per-PR/per-label against any repository that has review stacks enabled with `allow_with_label`/`prevent_with_label`. Full RCE (Critical, matching `Command`/`PTY.spawn`) requires the additional host/shell preconditions described above and is not independently verifiable from the engine's code alone.

### Likelihood Explanation
Low-to-moderate cost for the attacker to reach the vulnerable *key injection* itself: any unprivileged fork owner can label their own PR. Realizing full RCE via `BASH_ENV` additionally requires: (1) the deploy host's `/bin/sh` to be bash, (2) the particular dependency-step command line to be dispatched via `/bin/sh -c` (only happens when the command string contains shell metacharacters recognized by `Process.spawn`/`PTY.spawn`, e.g. `$`, quotes), and (3) a same-name file resolvable in the working directory. These are environment-specific and not guaranteed by shipit-engine's own code.

### Recommendation
Apply an explicit key allowlist/denylist to `ReviewStack#env`'s label-derived hash, mirroring `EnvironmentVariables#permit`: reject or filter out label-derived keys that collide with reserved/sensitive variable names (e.g. `PATH`, `BASH_ENV`, `ENV`, `IFS`, `LD_PRELOAD`, `RUBYOPT`, `RUBYLIB`, `BUNDLE_*`, `GEM_*`) and/or require label-derived variables to be defined in a stack-level allowlist analogous to `deploy_variables`/`rollback_variables`, so pull-request labels (webhook-controlled, attacker-influenceable) cannot introduce arbitrary environment keys into commands executed on the deploy host.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (illustrative)
test "#env allows fork-controlled labels to inject reserved variable names" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["bash_env"]

  # demonstrates the broken binding: no allowlist prevents BASH_ENV from being set
  assert_equal "true", stack.env["BASH_ENV"]
end

# test/lib/shipit/task_commands_test.rb (illustrative)
test "#install_dependencies process env includes attacker-controlled BASH_ENV from a PR label" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["bash_env"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  command = Shipit::TaskCommands.new(task).install_dependencies.first

  assert_equal "true", command.env["BASH_ENV"]
end
```
These assertions demonstrate the reachable, code-level part of the claim (unfiltered key injection into the dependency-step `Command#env`). They do not, and cannot within `test/` without a live shell/OS setup, prove that `BASH_ENV=true` alone results in code execution on an arbitrary deploy host, since that final step depends on `/bin/sh` being bash and on-disk file planting that are outside this engine's code.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
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
