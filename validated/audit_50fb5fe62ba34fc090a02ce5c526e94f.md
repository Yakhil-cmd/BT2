### Title
Attacker-controlled PR label named `PATH` overrides `Command#unbundled_env`'s safe `PATH`, enabling RCE on the deploy host - (File: `lib/shipit/command.rb`)

### Summary
`Shipit::ReviewStack#env` unconditionally converts every pull-request label into an environment variable (`label.upcase => "true"`) with no whitelist, and that hash flows unfiltered through `Shipit::TaskCommands#env` into `Shipit::Command#unbundled_env`, where `@env.stringify_keys` is merged last and therefore wins over the safe, prefixed `PATH` value. A label literally named `PATH` lets a PR author set `PATH=true` for every command Shipit executes against that review stack's checkout, including `bundle install` during `install_dependencies`, enabling arbitrary code execution via a same-named executable placed in the checked-out branch.

### Finding Description
The broken binding, stated as an explicit equality that fails: the set of environment variable keys Shipit is willing to accept from **any** label-derived source should equal the whitelist enforced by `Shipit::EnvironmentVariables#permit`/`VariableDefinition` (`app/models/shipit/variable_definition.rb`, `lib/shipit/environment_variables.rb`), i.e. `label_keys ⊆ allowed_variables`. This does not hold: `permit` is never invoked on `ReviewStack#env`'s label-derived hash. Its only callers are the API/task-definition variable paths (`app/controllers/shipit/api/base_controller.rb`, `app/models/shipit/task_definition.rb`), not the `Stack#env`/`ReviewStack#env`/`TaskCommands#env` chain.

Code path:
1. `Shipit::ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` on top of `Stack#env`, unfiltered. [1](#0-0) 
2. `Shipit::TaskCommands#env` merges `@stack.env` (containing the label-derived hash) into the final task environment, before `deploy_spec.machine_env` and `@task.env`. [2](#0-1) 
3. `install_dependencies` builds `Command.new(command_line, env:, chdir: steps_directory)`, where `steps_directory` defaults to `@task.working_directory` — the checked-out PR branch. [3](#0-2) [4](#0-3) 
4. `Command#unbundled_env` computes `BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)` — the attacker-controlled `@env['PATH']` value overwrites the safe `PATH` because it is merged last. [5](#0-4) 
5. `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`, executing every step (e.g. `bundle install`) with the attacker's `PATH` and inside the attacker's checked-out branch. [6](#0-5) 

Root cause: `capture_labels` in `LabelCapturingHandler` persists raw GitHub label names into `PullRequest#labels` with no filtering or reserved-word blocklist. [7](#0-6) 

Attacker exact request: open a PR against a repository that has `review_stacks_enabled` and an active review stack (created via `LabeledHandler`/`ReviewStackAdapter#create!`), add a label literally named `PATH` to that PR (triggers a genuine, correctly-signed `pull_request labeled` webhook from GitHub), and commit a `true/bundle` executable to the PR branch. When Shipit runs dependency-install or deploy steps for that review stack, `bundle` resolves to the attacker's script.

Existing guards do not stop this: `verify_signature`/`GitHubApp#verify_webhook_signature` only validate that the payload is a genuine GitHub webhook — they don't restrict label content. `ExplicitParameters` in `LabelCapturingHandler`/`LabeledHandler` only validates payload shape (`String`, `Integer`, presence), not label value semantics. `EnvironmentVariables#permit` exists but is never called on this path. No model validation restricts `PullRequest#labels` content. [8](#0-7) 

The existing test suite already demonstrates the unfiltered pass-through mechanism (with benign labels `WIP`/`BUG`), confirming the same code path a `PATH` label would traverse. [9](#0-8) [10](#0-9) 

### Impact Explanation
Arbitrary code execution on the Shipit deploy host, running under Shipit's own credentials (e.g. `GITHUB_TOKEN`, git committer identity, deploy secrets available to `Command`), triggered whenever a task/deploy/dependency-install runs against the affected review stack. Repeatable for any repository with `review_stacks_enabled` and an active review stack; blast radius is limited to the shared execution host, so any tenant's review stack processed on that host can compromise resources/secrets available to all stacks executing there. Matches "Critical - RCE on the deploy host via `Command`/`PTY.spawn`."

### Likelihood Explanation
Preconditions: `Shipit.review_stacks_enabled`/repository-level review stacks enabled, an active non-archived `Shipit::ReviewStack` tied to the PR, and the ability to add a label to that PR (granted to the attacker under this audit's threat model as "label their own PR") plus push a commit to the PR branch. No Shipit secrets, session, or elevated GitHub role are required — the webhook is a legitimate GitHub-signed event. Attacker cost is low (one label + one commit); feasibility is high and repeatable against any repository configured this way.

### Recommendation
Do not derive arbitrary environment variable names from PR label text. Either: (1) namespace label-derived variables (e.g. prefix with `SHIPIT_LABEL_` or similar) so they can never collide with reserved names like `PATH`, `HOME`, `LD_PRELOAD`, `BUNDLE_*`; (2) run label names through an explicit denylist/allowlist (reject reserved/base env keys) in `ReviewStack#env` before merging; or (3) change `Command#unbundled_env` so the safety-critical `PATH` (and other reserved vars) cannot be overridden by `@env`, e.g. compute `PATH` last and outside of `@env.stringify_keys`'s precedence, or explicitly strip disallowed keys from `@env` before merging.

### Proof of Concept
Add to `test/lib/shipit/task_commands_test.rb` (or a new unit test near `test/unit/command_test.rb`):
```ruby
test "#env allows a PR label literally named PATH to override the safe PATH" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["PATH"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env
  assert_equal "true", env["PATH"]

  command = Shipit::Command.new("bundle install", env: env, chdir: task.working_directory)
  refute_match(/\A#{Regexp.escape(Shipit.shell_paths.join(':'))}/, command.unbundled_env["PATH"])
  assert_equal "true", command.unbundled_env["PATH"]
end
```
Assert both sides of the binding: left side `Shipit::TaskCommands.new(task).env["PATH"]` (expected safe/prefixed value if the binding held) vs. right side (actual value `"true"` derived from the label) — the two diverge, proving `EXECUTION_TRUST` is broken.

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

**File:** lib/shipit/task_commands.rb (L17-21)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
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

**File:** lib/shipit/task_commands.rb (L92-98)
```ruby
    def steps_directory
      if sub_directory = deploy_spec.directory.presence
        File.join(@task.working_directory, sub_directory)
      else
        @task.working_directory
      end
    end
```

**File:** lib/shipit/command.rb (L85-101)
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
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/pull_request.rb (L14-14)
```ruby
    serialize :labels, coder: Shipit.serialized_column(:labels, type: Array)
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
