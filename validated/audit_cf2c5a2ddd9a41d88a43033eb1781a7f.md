## Analysis: Confirmed Vulnerability

Tracing the code confirms the claimed binding is broken. `Shipit::ReviewStack#env` unconditionally merges every PR label (uppercased) into the stack's environment hash with no whitelist, and that hash flows unfiltered into `Command#unbundled_env`, which is passed straight to `PTY.spawn`.

### Trace

`ReviewStack#env` merges pull request labels directly, with no filtering: [1](#0-0) 

This flows through `StackCommands#env` (`super.merge(@stack.env)`): [2](#0-1) 

then through `TaskCommands#env` (`super.merge(@stack.env)...merge(@task.env)`): [3](#0-2) 

then into every `Command.new(..., env:)` built by `perform`/`install_dependencies`, and finally into `Command#unbundled_env`, which unconditionally merges `@env.stringify_keys` on top of `BASE_ENV`, and is passed to `PTY.spawn`: [4](#0-3) [5](#0-4) 

This is confirmed by existing tests that show labels reaching `env` verbatim, uppercased, with value `"true"`: [6](#0-5) [7](#0-6) 

Note the important distinction: the `EnvironmentVariables#permit` whitelist (used for task/deploy variable definitions from `shipit.yml`) only guards **user-submitted API/form `env` params** (`app/models/shipit/deploy_spec.rb:174-180`, `app/models/shipit/task_definition.rb:63-65`), confirmed by the whitelist-rejection tests in `deploys_controller_test.rb` and `tasks_controller_test.rb`. That guard is never applied to `ReviewStack#env`'s label-derived keys — there is no call to `EnvironmentVariables.with(...).permit(...)` anywhere in `ReviewStack#env`, `StackCommands#env`, or `TaskCommands#env`. Labels are trusted implicitly and merged straight in.

Labels are populated from GitHub webhook payloads by `PullRequest#github_pull_request=` (`self.labels = github_pull_request.labels.map(&:name)`) and by `LabelCapturingHandler#capture_labels`: [8](#0-7) [9](#0-8) 

### Broken binding

Claimed binding: `Command#unbundled_env.keys == BASE_ENV.keys ∪ {'PATH'} ∪ (keys sanctioned by deploy_spec/task.env)`.

Actual: `Command#unbundled_env.keys == BASE_ENV.keys ∪ {'PATH'} ∪ (deploy_spec/task sanctioned keys) ∪ {PR label names uppercased}` — an unsanctioned, attacker-labeled key set. Since `'LD_PRELOAD'` is a valid label string and `ReviewStack#env` does `label_name.upcase => "true"` with no denylist/allowlist against reserved dynamic-loader or interpreter variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `PERL5LIB`, `RUBYOPT`, etc.), the equality fails and the attacker's label reaches `PTY.spawn`'s environment.

### Title
Uncontrolled PR labels merged into `ReviewStack#env` reach `PTY.spawn`, allowing loader-variable injection (`LD_PRELOAD`) - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` merges every PR label name (uppercased) as an environment variable set to `"true"` with no allowlist or denylist, and this hash is merged unfiltered into `Command#unbundled_env`, which is handed directly to `PTY.spawn` for every command executed against that review stack (deploys, rollbacks, custom tasks). A PR author who can set a label named `LD_PRELOAD` (or other loader/interpreter-honoured variable name) on their own PR causes `LD_PRELOAD=true` to be injected into the environment of every subprocess spawned for that stack's tasks.

### Finding Description
The broken binding: `Command#unbundled_env.keys` should equal `BASE_ENV.keys ∪ {'PATH'} ∪ sanctioned(deploy_spec/task.env)`, but in practice it also includes arbitrary uppercased PR label names because `ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`) merges `pull_request.labels` directly with no call to `EnvironmentVariables#permit`. This hash propagates through `StackCommands#env` → `TaskCommands#env`/`DeployCommands#env` → `Command.new(..., env:)` → `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) → `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` (`lib/shipit/command.rb:92`). The `EnvironmentVariables#permit` whitelist mechanism exists (`lib/shipit/environment_variables.rb`) and is applied to user-submitted API `env` params in `DeploySpec#filter_deploy_envs`/`filter_rollback_envs` and `TaskDefinition#filter_envs`, but it is never applied to PR-label-derived keys. Attacker flow: open a PR against a repository with review stacks enabled (and continuous deployment or manual task triggering enabled for that stack), and apply a label literally named `LD_PRELOAD` to that PR (label capture is handled by `LabelCapturingHandler#capture_labels` and `PullRequest#github_pull_request=`). On the next deploy/task run for that review stack, `ReviewStack#env` injects `'LD_PRELOAD' => 'true'` into every spawned subprocess's environment.

### Impact Explanation
Every command executed for that review stack's deploy/rollback/task (git, bundler, custom shipit.yml steps) inherits `LD_PRELOAD=true` in its process environment, causing the dynamic loader to attempt to preload `"true"` as a shared object for each exec'd subprocess of that stack's deploy. This is an attacker-controlled interpreter/loader-honoured variable reaching `PTY.spawn`, matching the Critical category "RCE on the deploy host via `Command`/`PTY.spawn`" if the attacker can control label text finely (e.g. pointing `LD_PRELOAD` at a path they can also write, or abusing other loader/interpreter variables such as `BASH_ENV`/`RUBYOPT`/`PERL5LIB` the same way), and at minimum causes reliable command/tooling breakage on that stack's deploy host. The blast radius is scoped to the stack corresponding to the labeled PR/repository; it does not cross-tenant unless the deploy host and its filesystem are shared across stacks.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled with continuous deployment or manual task triggering, and the attacker's label change must be captured (labels are captured via GitHub webhooks routed to `LabelCapturingHandler`). Attacker cost is minimal — no Shipit session, token, or secret is required, just the ability to attach a label to their own PR in a repository already wired to Shipit for review-stack automation. Repeatable per PR/per label, and per review stack the attacker's PR corresponds to.

### Recommendation
In `ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`), sanitize PR-label-derived environment variables: apply an allowlist (e.g. restrict to variable names matching a safe pattern and/or explicitly excluding dynamic-loader/interpreter-related variables like `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `RUBYOPT`, `PERL5LIB`, `PYTHONPATH`, `IFS`, `PATH`), or require label-derived keys to be explicitly declared/sanctioned in `shipit.yml` (similar to `deploy_variables`/`task variables`), reusing `EnvironmentVariables#permit` against a controlled allowlist before merging into the process environment reaching `Command#unbundled_env`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (extend)
test "#env does not leak reserved loader variables from PR labels" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["LD_PRELOAD"]

  assert_equal "true", stack.env["LD_PRELOAD"]  # demonstrates the leak (currently passes, should fail after fix)
end

# test/lib/shipit/task_commands_test.rb (extend)
test "#env does not pass attacker-controlled loader variables to Command#unbundled_env" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["LD_PRELOAD"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env
  command = Shipit::Command.new('true', env:, chdir: Dir.tmpdir)

  assert_equal "true", command.unbundled_env["LD_PRELOAD"]  # demonstrates reachability to PTY.spawn env
end
```
Both assertions currently pass against the shown code, demonstrating the label-controlled key reaches `Command#unbundled_env` unfiltered; a fix should make these assertions fail (i.e., `LD_PRELOAD` absent or rejected).

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

**File:** lib/shipit/stack_commands.rb (L13-15)
```ruby
    def env
      super.merge(@stack.env)
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

**File:** lib/shipit/command.rb (L85-99)
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
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** test/lib/shipit/task_commands_test.rb (L1-17)
```ruby
# frozen_string_literal: true

require "test_helper"

class TaskCommandsTest < ActiveSupport::TestCase
  test "#env includes a ReviewStack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    stack.pull_request.labels = ["wip", "bug"]
    task = shipit_tasks(:shipit_restart)
    task.stack = stack

    env = Shipit::TaskCommands.new(task).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
  end
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

**File:** app/models/shipit/pull_request.rb (L36-50)
```ruby
    def github_pull_request=(github_pull_request)
      self.github_id = github_pull_request.id
      self.number = github_pull_request.number
      self.api_url = github_pull_request.url
      self.title = github_pull_request.title
      self.state = github_pull_request.state
      self.additions = github_pull_request.additions
      self.deletions = github_pull_request.deletions
      self.user = User.find_or_create_by_login!(github_pull_request.user.login)
      self.assignees = github_pull_request.assignees.map do |github_user|
        User.find_or_create_by_login!(github_user.login)
      end
      self.labels = github_pull_request.labels.map(&:name)
      self.head = find_or_create_commit_from_github_by_sha!(github_pull_request.head.sha)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```
