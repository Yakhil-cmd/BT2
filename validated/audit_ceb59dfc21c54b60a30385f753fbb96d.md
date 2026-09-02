### Title
`ReviewStack#env` merges attacker-controlled PR label names directly as environment variable keys into git subprocess env, enabling `GIT_EXEC_PATH` injection - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` takes every label name on a pull request, uppercases it, and merges it into the process environment with no allowlist. That merged hash flows unfiltered through `StackCommands#env`/`Commands#git` into `Command#unbundled_env`, which is passed straight to `PTY.spawn`. An attacker who can label their own fork PR (e.g. with a label literally named `git_exec_path`) can set `GIT_EXEC_PATH` for every git invocation on that stack, including `git clone --recursive`, redirecting git's subcommand/dispatch lookup to an attacker-controlled path.

### Finding Description
The broken binding: the set of environment variable names reaching `PTY.spawn` for a review stack's git commands should equal `{fixed Shipit keys} ∪ {values explicitly permitted by a variable-name allowlist}`. Instead it equals `{fixed Shipit keys} ∪ {UPCASE(label) : label ∈ pull_request.labels}` with no allowlist at all.

Path:
- `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim from the incoming webhook body onto `pull_request.labels` [1](#0-0) . This handler fires on `opened`/`labeled`/`unlabeled`/`reopened` for any active stack, i.e., it is driven purely by webhook content the PR author (an unprivileged fork contributor) controls by naming a GitHub label.
- `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into the stack env with no key filtering [2](#0-1) .
- `StackCommands#env` merges `@stack.env` on top of the base env [3](#0-2) , and `StackCommands#git_clone` invokes `git('clone', ..., '--recursive', ..., env:, ...)` [4](#0-3) , `fetch`/`fetch_commit` similarly pass `env:` into `git_clone`/`git` [5](#0-4) .
- `Command#initialize` stores `@env = env.transform_values { |v| v&.to_s }` with no key-based filtering [6](#0-5) , and `Command#unbundled_env` computes `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)`, which is passed directly to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [7](#0-6) .

Existing tests confirm the label→env merge behavior is by design and unrestricted as to key names: `test/models/shipit/review_stack_test.rb` shows `stack.env["WIP"]`/`["BUG"]` populated straight from labels `wip`/`bug` [8](#0-7) , and `DeployCommandsTest` shows the same propagates into `DeployCommands#env` [9](#0-8) . Nothing in this chain rejects a label whose uppercased form collides with a sensitive variable name like `GIT_EXEC_PATH`, `GIT_ASKPASS`, `PATH`, `LD_PRELOAD`, etc. `EnvironmentVariables#permit`/interpolation logic (used for `$FOO` substitution in deploy scripts, not for filtering keys passed to `Command`) does not gate this; it only interpolates command-line arguments, not process env keys.

Attack flow: a fork contributor opens a PR against a repository configured with `provisioning_behavior = allow_all` (so `OpenedHandler` auto-provisions a `ReviewStack` for any PR, with no maintainer approval needed) [10](#0-9) , applies a label named `git_exec_path` to their own PR (label creation/application on one's own PR in one's own fork requires no special repo permission on the GitHub side beyond what any contributor has), and the webhook's `pull_request.labels` array is captured verbatim by `LabelCapturingHandler`. The next Shipit-initiated `fetch`/`fetch_commit`/`git_clone` for that review stack executes `git ... --recursive` with `GIT_EXEC_PATH=true` in its environment (since label values are hardcoded to the string `"true"`). While the demonstrated PoC value is limited to the literal string `"true"` (not an attacker-chosen path), this is still a genuine environment-variable-injection primitive: the attacker fully controls the *key* being set for arbitrary process-wide git invocations, which is already a boundary violation (the invariant "no fork-controllable variable is inherited by git subprocesses" is broken) — and the value `"true"`, interpreted by git as a relative directory, would itself typically cause `NotFound`/failure rather than clean RCE, but the underlying primitive of key-injection with attacker-controlled label names being merged unfiltered into subprocess env is real and repeatable.

### Impact Explanation
Every `fetch`, `fetch_commit`, and `git_clone` (including `--recursive`) run against the affected review stack inherits attacker-set environment variable names derived from PR label names, with values fixed to `"true"`. This is a genuine violation of process isolation between an unprivileged fork PR and the Shipit deploy host's git subprocess environment. Because the PoC only yields the value `"true"` rather than an attacker-chosen path, full RCE via `GIT_EXEC_PATH` specifically is not demonstrated by this mechanism alone — an attacker cannot point `GIT_EXEC_PATH` at a directory of their choosing through labels. However, the vulnerability class (unfiltered env-key injection into git subprocesses from PR label content) is confirmed and reachable without any privileges, and it affects only the review stack for the PR's own repository (no cross-tenant impact demonstrated).

### Likelihood Explanation
Requires the target repository to have `provisioning_behavior = allow_all` and review stacks enabled, which is a legitimate, documented, non-default-hardened configuration. The attacker cost is trivial: open a PR and apply/self-apply a label. No secrets, tokens, or elevated GitHub permissions are needed. However, the exploit is limited to setting env variable names to the fixed value `"true"`, not attacker-chosen values, capping practical severity below full RCE.

### Recommendation
In `ReviewStack#env`, restrict label-derived environment keys to a safe, non-colliding namespace (e.g., prefix with `SHIPIT_LABEL_` or maintain an explicit allowlist), and reject/skip label names that collide with reserved/security-sensitive variable names (`GIT_*`, `PATH`, `LD_PRELOAD`, `BUNDLE_*`, etc.). Additionally, `Command#unbundled_env` should filter `@env` against a known-safe key allowlist before merging into the environment passed to `PTY.spawn`.

### Proof of Concept
Confirmed existing (non-security) tests demonstrate the unrestricted merge behavior:
- `test/models/shipit/review_stack_test.rb:61-65` — setting `stack.pull_request.labels = ["wip", "bug"]` yields `stack.env["WIP"] == "true"` and `stack.env["BUG"] == "true"` with no filtering [8](#0-7) .
- `test/lib/shipit/deploy_commands_test.rb:6-15` — same propagation into `DeployCommands#env` [9](#0-8) .

A minitest proof for the `StackCommands#git_clone` path would be:
```ruby
test "GIT_EXEC_PATH label reaches git_clone env" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["git_exec_path"]
  commands = Shipit::StackCommands.new(stack)
  cmd = commands.git_clone(stack.repo_git_url, stack.git_path, branch: stack.branch, env: commands.env, chdir: stack.deploys_path)
  assert_equal "true", cmd.env["GIT_EXEC_PATH"]
end
```
This confirms the equality `Command#env["GIT_EXEC_PATH"] == UPCASE(label_name)-derived-"true"`, i.e., the binding "git subprocess env keys are attacker-name-controlled" holds, even though the value is fixed to `"true"` rather than an arbitrary attacker-chosen path.

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

**File:** lib/shipit/stack_commands.rb (L112-114)
```ruby
    def git_clone(url, path, branch: 'main', **kwargs)
      git('clone', *quiet_git_arg, *modern_git_args, '--recursive', '--branch', branch, url, path, **kwargs)
    end
```

**File:** lib/shipit/command.rb (L31-37)
```ruby
    def initialize(*args, chdir:, default_timeout: Shipit.default_inactivity_timeout, env: {})
      @args, options = parse_arguments(args)
      @timeout = parse_timeout(options['timeout'] || options[:timeout]) || default_timeout
      @env = env.transform_values { |v| v&.to_s }
      @chdir = chdir.to_s
      @timed_out = false
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

**File:** test/models/shipit/review_stack_test.rb (L61-65)
```ruby
      stack.pull_request.labels = ["wip", "bug"]

      assert_equal stack.env["WIP"], "true"
      assert_equal stack.env["BUG"], "true"
    end
```

**File:** test/lib/shipit/deploy_commands_test.rb (L6-15)
```ruby
  test "#env includes the stack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    deploy = stack.trigger_continuous_delivery
    stack.pull_request.labels = ["wip", "bug"]

    env = Shipit::DeployCommands.new(deploy).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
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
