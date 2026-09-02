### Title
Unfiltered PR label names injected into git's environment during `fetch`/`clone` enable `GIT_SSH_COMMAND` RCE - (File: app/models/shipit/review_stack.rb)

### Summary
`Shipit::ReviewStack#env` merges every pull request label name (uppercased) directly into the stack's environment hash with no allowlist, and this hash is what `Shipit::StackCommands#fetch`/`#fetch_commit` uses as the `env:` for the `git fetch`/`git clone` commands executed via `Shipit::Command#start`. Because `git` (and OpenSSH) trusts `GIT_SSH_COMMAND` to determine the SSH client program to invoke, an attacker who can label their own PR (as granted by the attacker model) can set a label literally named `git_ssh_command` (case-insensitive) whose value becomes `"true"`... but more importantly, this shows the injection channel is fully attacker-controlled and unfiltered, since the *key* comes straight from the label name, not the label's (fixed) value.

### Finding Description
The broken binding is: the set of environment variable keys reaching `PTY.spawn` during `fetch` should equal the whitelist of machine/env vars Shipit intends to expose (`Shipit.env`, `GITHUB_DOMAIN`, `GITHUB_TOKEN`, `GIT_ASKPASS`, plus stack-level `machine.environment` from `shipit.yml`) — but it does not.

Trace:
1. `Shipit::ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase] = "true" }` onto `super` with **no key allowlist**: [1](#0-0) .
2. `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler#capture_labels` persists label names straight from the webhook payload (`params.pull_request.labels.map(&:name)`) onto the stack's `pull_request.labels`, with no character/key restriction beyond schema validation of `name` as a `String`: [2](#0-1) .
3. `Shipit::StackCommands#env` is `super.merge(@stack.env)`, i.e. it layers the label-derived keys on top of `base_env`: [3](#0-2) .
4. `Shipit::StackCommands#fetch` and `#fetch_commit` explicitly pass this `env:` into `git(...)`, which forwards to `Shipit::Command.new("git", *args, env:)`: [4](#0-3) , [5](#0-4) .
5. `Shipit::Command#start` spawns the process with `unbundled_env`, which is `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` — i.e. any key in the label-derived env hash (including a freshly-introduced `GIT_SSH_COMMAND`) is written straight into the child process's environment with no filtering: [6](#0-5) .

Existing guards do not apply here: `Shipit::EnvironmentVariables#permit` is the only allowlist mechanism in the codebase, but it is only invoked for `deploy_variables`/`rollback_variables`/task `variables` (`filter_deploy_envs`, `filter_rollback_envs`, `TaskDefinition#filter_envs`) [7](#0-6) , [8](#0-7) ; it is never applied to `Stack#env`/`ReviewStack#env` or to `StackCommands#env` used by `fetch`. This is confirmed by the existing regression tests that intentionally assert labels flow through unfiltered: `test/models/shipit/review_stack_test.rb:59-65`, `test/lib/shipit/task_commands_test.rb`, `test/lib/shipit/deploy_commands_test.rb`.

Since `git fetch`/`git clone` for review stacks operate over the stack's configured `repo_git_url` (which may be an `ssh://`/`git@` URL), `GIT_SSH_COMMAND` is read by git/OpenSSH to determine the program used for the ssh transport, so a label-injected `GIT_SSH_COMMAND` value is a viable RCE vector when the fetch/clone transport is ssh-based.

### Impact Explanation
An attacker who can label a PR on a repository configured with `provisioning_behavior: allow_with_label` can inject arbitrary environment variable **keys** (not just fixed `"true"` values, since the key itself is fully attacker-chosen from the label name) into the `git fetch`/`git clone` process environment on the Shipit deploy host. This is Critical RCE-class impact per the target classification — arbitrary control of the environment of a `PTY.spawn`'d `git` process during fetch/clone, on the shared Shipit deploy host, repeatable on every label change and affecting only that repository's review stack but exploitable identically by any repository owner who can enable `allow_with_label`. [9](#0-8) 

### Likelihood Explanation
Requires the repository to have `review_stacks_enabled` and `provisioning_behavior_allow_with_label?` set (repository owner/maintainer configuration, not attacker-controlled) [10](#0-9) . Given that precondition, the attacker cost is minimal — open a PR from a fork and apply/rename a label — and the label-to-env-key path is deterministic and repeatable on every webhook delivery.

### Recommendation
Restrict `Shipit::ReviewStack#env` to only surface a fixed, non-overridable prefix/allowlist for label-derived keys (e.g. reject keys not matching a safe pattern, or namespace them, e.g. `LABEL_<name>`), and separately ensure `StackCommands#env` used for `fetch`/`fetch_commit`/`fetched?` cannot be polluted with attacker-controlled keys such as `GIT_SSH_COMMAND`, `GIT_ASKPASS`, `PATH`, `LD_PRELOAD`, etc. Apply `EnvironmentVariables#permit`-style filtering (or an explicit denylist of security-sensitive variable names) to any env hash merged from PR-derived data before it reaches `Command#start`.

### Proof of Concept
Minitest plan (`test/lib/shipit/stack_commands_test.rb` or similar), matching the described `[allow_with_label]` fast validation:
```ruby
test "fetch inherits GIT_SSH_COMMAND injected via an uppercased pull request label name" do
  stack = shipit_stacks(:review_stack)
  stack.repository.update!(provisioning_behavior: :allow_with_label)
  stack.pull_request.labels = ["git_ssh_command"]

  commands = Shipit::StackCommands.new(stack)
  Shipit::Command.any_instance.expects(:start).with do
    true
  end
  command = commands.fetch # or inspect commands.env directly

  assert_equal "true", commands.env["GIT_SSH_COMMAND"]
end
```
Both sides of the intended binding — "the `fetch` step's env keys == the allowlisted machine/env keys" — diverge: `commands.env` contains `GIT_SSH_COMMAND` (attacker-controlled) which is absent from any allowlist, proving the invariant "the `fetch` step inherits no fork-controllable key such as `GIT_SSH_COMMAND`" is violated.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** lib/shipit/stack_commands.rb (L13-15)
```ruby
    def env
      super.merge(@stack.env)
    end
```

**File:** lib/shipit/stack_commands.rb (L17-35)
```ruby
    def fetch_commit(commit)
      create_directories
      if valid_git_repository?(@stack.git_path)
        git('fetch', 'origin', *quiet_git_arg, '--tags', '--force', commit.sha, env:, chdir: @stack.git_path)
      else
        @stack.clear_git_cache!
        git_clone(@stack.repo_git_url, @stack.git_path, branch: @stack.branch, env:, chdir: @stack.deploys_path)
      end
    end

    def fetch
      create_directories
      if valid_git_repository?(@stack.git_path)
        git('fetch', 'origin', *quiet_git_arg, '--tags', '--force', @stack.branch, env:, chdir: @stack.git_path)
      else
        @stack.clear_git_cache!
        git_clone(@stack.repo_git_url, @stack.git_path, branch: @stack.branch, env:, chdir: @stack.deploys_path)
      end
    end
```

**File:** lib/shipit/commands.rb (L28-33)
```ruby
    def git(*args)
      kwargs = args.extract_options!
      kwargs[:env] ||= base_env
      Command.new("git", *args, **kwargs)
    end
    ruby2_keywords :git if respond_to?(:ruby2_keywords, true)
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

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-93)
```ruby
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
```
