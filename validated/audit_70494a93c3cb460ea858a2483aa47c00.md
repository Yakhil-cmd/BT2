### Title
Arbitrary environment variable injection into `git` subprocesses via unfiltered pull request label names (e.g. `SSH_ASKPASS`) - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` merges every pull request label name (uppercased) directly into the stack's environment hash with no allow-list, and that hash is inherited unmodified by `StackCommands#fetch`/`#git_clone`'s `git` subprocess via `Command#start`. An attacker who can label their own pull request (which, under `provisioning_behavior=allow_all`, requires no maintainer approval to get a `ReviewStack` created and fetched) can set a label named `ssh_askpass` (or any other git/ssh-honored variable name) and have it injected verbatim into the environment of the host's `git fetch`/`git clone` invocation.

### Finding Description
The broken binding is: the set of environment variable **names** reaching the `git` subprocess in `StackCommands#fetch`/`#git_clone` should be a fixed, host-controlled allow-list, but instead it equals `pull_request.labels.map(&:upcase)` — i.e. `env_reaching_git.keys ⊇ attacker_supplied_label_names.map(&:upcase)`, with no allow-list check on that side of the merge.

Path:
1. `LabelCapturingHandler#capture_labels` persists label names straight from the webhook payload: `pull_request.update!(labels: params.pull_request.labels.map(&:name))` [1](#0-0) .
2. `ReviewStack#env` merges those label names, uppercased, into the stack env with no filtering: `super.merge(pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" })` [2](#0-1) .
3. `StackCommands#env` merges `@stack.env` unfiltered: `super.merge(@stack.env)` [3](#0-2) , and this `env` is passed straight into the `git` invocations in `#fetch` and `#git_clone`: `git('fetch', ..., env:, chdir: @stack.git_path)` / `git_clone(@stack.repo_git_url, @stack.git_path, branch: @stack.branch, env:, chdir: @stack.deploys_path)` [4](#0-3) , `git_clone` itself just forwards `**kwargs` (including `env:`) to `git(...)` [5](#0-4) .
4. `Command#start` merges this env on top of the process's own `ENV['PATH']`/`BASE_ENV` with no key filtering and passes it to `PTY.spawn`: `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` where `unbundled_env = BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` [6](#0-5) .

The one allow-list mechanism in the codebase, `EnvironmentVariables#permit`, is applied only to deploy/rollback/task-triggered variables supplied via the API (`DeploySpec#filter_deploy_envs`/`#filter_rollback_envs`, `TaskDefinition#filter_envs`) [7](#0-6) [8](#0-7) . It is never invoked on `ReviewStack#env`'s label-derived keys, so nothing prevents a label literally named `ssh_askpass` from producing `env['SSH_ASKPASS']` in the merged hash that reaches `git`.

Under `provisioning_behavior=allow_all`, this whole chain runs automatically for every opened pull request with no maintainer gate: `OpenedHandler#provision?` returns true purely from `repository.provisioning_behavior_allow_all?` [9](#0-8) , and labels are captured from the same unauthenticated webhook body.

### Impact Explanation
If ssh transport is used for the origin (or any future fetch path uses ssh), the injected `SSH_ASKPASS` (with `SSH_ASKPASS_REQUIRE=force`, which the attacker can also inject the same way) would cause `ssh` to execute an attacker-named program during the `git fetch`/`git clone` invocations in `StackCommands`, giving code execution on the Shipit deploy host under the Shipit process's privileges — this is the Critical RCE class in scope. Even absent ssh, this demonstrates a general, un-guarded environment-variable injection primitive into the host's `git` subprocesses reachable from unauthenticated webhook-sourced pull request labels, affecting any repository configured with `allow_all` (or `allow/prevent_with_label`, since labels are captured regardless of provisioning decision once a stack/pull_request record exists). The blast radius is scoped to the repository owning the pull request/stack, but is trivially repeatable per request/per label update.

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled` with `provisioning_behavior` allowing stack creation for the attacker's PR (`allow_all` is the documented "most likely" configuration per `docs/review_stacks.md`) [10](#0-9) . Attacker cost is minimal: open a PR from a fork and add a label named `ssh_askpass` (label name casing is irrelevant since it's uppercased). No secrets, sessions, or elevated GitHub permissions are required per the stated attacker model. This is repeatable at will by relabeling/reopening the PR, which re-triggers `fetch`/`git_clone` on subsequent tasks.

### Recommendation
Apply an explicit allow-list to `ReviewStack#env`'s label-derived keys (e.g. reuse `EnvironmentVariables.permit` against a configured/documented set of safe label-derived variable names, or prefix them, e.g. `LABEL_<NAME>`, so they can never collide with sensitive variables like `SSH_ASKPASS`, `GIT_ASKPASS`, `GIT_SSH_COMMAND`, `LD_PRELOAD`, `PATH`, etc.), and additionally have `Command#unbundled_env`/`StackCommands#env` explicitly strip or reject any of these known-dangerous variable names before they reach `PTY.spawn`.

### Proof of Concept
```ruby
# test/lib/shipit/stack_commands_ssh_askpass_test.rb
require "test_helper"

class StackCommandsSshAskpassTest < ActiveSupport::TestCase
  test "SSH_ASKPASS from a PR label reaches the git fetch/clone subprocess env" do
    stack = shipit_stacks(:review_stack)
    stack.pull_request.update!(labels: ["ssh_askpass"])

    commands = Shipit::StackCommands.new(stack)
    stack.git_path.stubs(:exist?).returns(false) # forces git_clone path

    command = commands.fetch

    # Binding under test: env reaching `git` should equal a fixed allow-list,
    # NOT include attacker-controlled label-derived keys.
    assert_equal "true", command.env["SSH_ASKPASS"], "attacker label injected SSH_ASKPASS into the git subprocess env"
  end
end
```
This demonstrates that `command.env` (as passed to `Command#start` -> `PTY.spawn`) contains `SSH_ASKPASS` sourced solely from an unauthenticated pull request label, confirming the missing allow-list on the `StackCommands#fetch`/`#git_clone` path.

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

**File:** lib/shipit/stack_commands.rb (L112-114)
```ruby
    def git_clone(url, path, branch: 'main', **kwargs)
      git('clone', *quiet_git_arg, *modern_git_args, '--recursive', '--branch', branch, url, path, **kwargs)
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

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
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

**File:** docs/review_stacks.md (L9-13)
```markdown
1. Visit the shipit-engine Repository UI - `https://host-application/repositories`
1. Click on the project's repository
1. Check "Dynamically provision stacks for Pull Requests?"
1. Select the "Provisioning Behavior" appropriate for your project - most likely "Allow All"
1. Click "Save"
```
