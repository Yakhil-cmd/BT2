### Title
Unfiltered pull-request label names injected as environment keys reach `Command#unbundled_env`/`PTY.spawn` during the `fetch` phase - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) into the stack's environment hash with a fixed value of `"true"`, with no allowlist. This merged hash is consumed unmodified by `StackCommands#env` and passed straight through to `Command#unbundled_env`, which is merged into the process environment given to `PTY.spawn` for the `fetch`/`git clone` operations, before any `EnvironmentVariables#permit` filtering is applied.

### Finding Description
The broken binding: the invariant claimed is `fetch_step_env keys ⊆ deploy_spec_declared_variables`, but the actual code produces `fetch_step_env keys = BASE_ENV keys ∪ Shipit.env keys ∪ pull_request.labels.map(&:upcase)`, with no intersection against any allowlist.

Trace:
- `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into the stack env with no key filtering: [1](#0-0) .
- Labels are persisted directly from the incoming webhook body without any allowlist on names: `pull_request.update!(labels: params.pull_request.labels.map(&:name))` in `LabelCapturingHandler#capture_labels` [2](#0-1) .
- `StackCommands#env` merges this stack env straight through with no sanitization: `super.merge(@stack.env)` [3](#0-2) .
- The `fetch` method builds the `git` command using this same unsanitized `env:` [4](#0-3) .
- `Command#unbundled_env` merges `@env.stringify_keys` directly into `BASE_ENV`/`PATH`, and `Command#start` passes this to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` with no filtering: [5](#0-4) .
- The only sanitization primitive in the codebase, `EnvironmentVariables#permit`, is applied solely to `deploy_variables`/`rollback_variables`/task `variables` (`DeploySpec#filter_deploy_envs`, `#filter_rollback_envs`, `TaskDefinition#filter_envs`) — it is never invoked on the stack/review-stack `env` used by `fetch`/`fetch_commit`/`fetched?`: [6](#0-5) [7](#0-6) .

Existing tests confirm the unfiltered pass-through is intentional/expected behavior, not merely theoretical: `test/models/shipit/review_stack_test.rb:59-65` and `test/lib/shipit/deploy_commands_test.rb:6-15` both assert that arbitrary uppercased label names appear verbatim as top-level env keys with value `"true"`. [8](#0-7) [9](#0-8) 

Attacker's exact request: open a fork PR against a repository configured with `provisioning_behavior: allow_all` and `review_stacks_enabled: true` (a `ReviewStack` gets auto-created per `OpenedHandler#provision?` [10](#0-9) ), then attach a label literally named `GIT_CONFIG_GLOBAL` to that PR (any GitHub user who can label their own PR, or who can forge/replay the `labeled` webhook body since this only requires labels present in the payload the handler trusts). When Shipit's `fetch` step runs for that review stack, `GIT_CONFIG_GLOBAL=true` is present in the subprocess environment given to `git`.

Why existing guards fail: `verify_signature`/webhook signature checks only validate that the request came from configured GitHub, not the content of `labels[]`; nothing in `LabelCapturingHandler`, `ReviewStack#env`, or `Command` enforces a key allowlist for this particular env source, unlike the deploy/rollback/task env paths which do call `EnvironmentVariables#permit`.

Important caveat/limitation discovered: the injected value is hard-coded to the literal string `"true"` (not attacker-controlled content), so `GIT_CONFIG_GLOBAL=true` only becomes a meaningful attack (loading a malicious git config defining `core.fsmonitor`/hook commands) if a file literally named `true` exists at the path git resolves it against in the stack's working/cache directory — which the attacker could plant by committing a file named `true` into their own fork branch, since the review stack's git cache is populated from that attacker-controlled branch. I could not fully verify from available code/context whether `Stack#git_path` is a bare or working-tree clone, or the exact working directory contents at the point subsequent `git fetch` commands run, which affects whether the "true"-named file would be resolvable at the moment `GIT_CONFIG_GLOBAL` is evaluated. This detail could not be confirmed with the tools available and would need to be verified in the full checkout to establish a complete RCE chain; the environment-injection primitive itself, however, is fully confirmed in code.

### Impact Explanation
Confirmed: an attacker-chosen environment variable key (fixed value `"true"`) reaches the environment of every `git` subprocess spawned for that review stack's `fetch`/`fetch_commit`/`fetched?` commands via `PTY.spawn`, for any repository/stack that has review stacks enabled with `allow_all` (or allow-with-label, if the attacker can apply that label too). This is a genuine violation of environment isolation between deploy-time git operations and untrusted PR metadata, scoped to the attacker's own review stack (their own PR/fork), not cross-tenant. Whether this converts into full command execution depends on the attacker also controlling file content at a path resolvable as `GIT_CONFIG_GLOBAL=true` within that same stack's git cache directory — this part is plausible given the attacker fully controls their own fork's checked-out content, but was not conclusively traced end-to-end here.

### Likelihood Explanation
Preconditions: repository must have `review_stacks_enabled: true` and `provisioning_behavior: allow_all` (or `allow_with_label` plus the ability to add that label). Attacker cost is low — opening a PR and adding a label named `GIT_CONFIG_GLOBAL` requires no privileges beyond forking and labeling their own PR. The env-key-injection step is trivially repeatable per request. The step from injected key to actual code execution requires the attacker to also plant a file named `true` at the correct resolution path in their own branch, which was not fully verified.

### Recommendation
Apply an explicit key allowlist to the label-derived environment before merging it anywhere near `Command`/`git`: strip any label name that collides with sensitive `GIT_*` / `PATH` / process-control variable names, or better, isolate label flags into a clearly namespaced prefix (e.g., `SHIPIT_LABEL_<NAME>`) instead of merging raw uppercased label names directly into the top-level process environment. Additionally, route `ReviewStack#env`/`StackCommands#env` through `EnvironmentVariables#permit` (or an equivalent allowlist) before it reaches `Command#unbundled_env`, consistent with how `deploy_variables`/`rollback_variables`/task `variables` are already sanitized.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (new test)
test "#env injects fork-controllable keys reachable by fetch's Command" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["GIT_CONFIG_GLOBAL"]

  env = stack.env
  assert_equal "true", env["GIT_CONFIG_GLOBAL"]

  commands = Shipit::StackCommands.new(stack)
  fetch_command = commands.fetch
  assert_equal "true", fetch_command.env["GIT_CONFIG_GLOBAL"]
  assert_equal "true", fetch_command.unbundled_env["GIT_CONFIG_GLOBAL"]
end
```
This demonstrates the equality violation: expected `fetch_command.unbundled_env.keys ⊆ allowlisted_keys` is false because `"GIT_CONFIG_GLOBAL"` (fork-controlled label name) is present in the env passed toward `PTY.spawn`.

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

**File:** lib/shipit/stack_commands.rb (L27-35)
```ruby
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
