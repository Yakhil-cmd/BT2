### Title
Attacker-controlled PR label named `PATH` overwrites the sanitized `PATH` in `Command#unbundled_env`, enabling command-hijack RCE on the deploy host - ([File: lib/shipit/command.rb])

### Summary
`Shipit::ReviewStack#env` converts every PR label into an environment variable named `LABEL.upcase => "true"` with no key blacklist, and `Shipit::Command#unbundled_env` merges the task's `@env` hash *after* it sets the safe, `Shipit.shell_paths`-derived `PATH`. An attacker who opens a PR against their own fork and labels it literally `PATH` can therefore replace the real `PATH` used by `PTY.spawn` with the string `"true"`, a relative path that resolves against the current working directory — which, for a `ReviewStack`, is the attacker's own checked-out branch content.

### Finding Description
The binding claimed broken: the key `'PATH'` written by `Command#unbundled_env` should always equal `"#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"`. This equality is violated because:

- `Shipit::ReviewStack#env` builds `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` and merges it over the base stack env with no reserved-key filtering. [1](#0-0) 
- `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim onto `PullRequest#labels` for any labeling event on an active, non-archived stack, with no validation of the label string (confirmed by the existing test accepting arbitrary unicode/emoji label names). [2](#0-1) [3](#0-2) 
- `Shipit::Command#unbundled_env` computes `BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)` — since `@env` (which flows from `TaskCommands#env` → `@stack.env` → `ReviewStack#env`) is merged last, a `PATH` key inside it silently overwrites the intended safe `PATH`. [4](#0-3) 
- This corrupted env is passed straight into `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`. [5](#0-4) 

Existing tests confirm the label→env flow is by design and unfiltered (`env["WIP"]`, `env["BUG"]` etc. are asserted, with no key exclusion list), which shows there is no guard preventing a label named `PATH` from reaching `Command#env`. [6](#0-5) [7](#0-6) 

`EnvironmentVariables#permit` — the only whitelist mechanism in the codebase — is a separate, opt-in sanitizer used for user/API-supplied deploy env parameters and machine_env interpolation; it is never invoked on the label-derived hash produced by `ReviewStack#env`, so it does not protect this path. [8](#0-7) 

Exploit flow: attacker opens a PR from a fork against a repository that has `review_stacks` enabled, gets (or creates) an active, non-archived `ReviewStack`, and adds a label literally named `PATH` (case-insensitive, since it's uppercased). On the next `labeled` webhook, `LabelCapturingHandler` persists this into `PullRequest#labels`. On the review stack's next deploy/task, `TaskCommands#env` → `ReviewStack#env` injects `'PATH' => 'true'`, and `Command#unbundled_env` lets it clobber the real `PATH`. Because the label value is hard-coded to the literal string `"true"` (not attacker-chosen text), the resulting `PATH` is the relative directory name `true`. Since the `chdir` for these commands is inside the checked-out working directory built from the attacker's own PR branch content (which the attacker fully controls for their own review stack), the attacker can commit a directory named `true/` containing executables named after commands invoked in later steps (e.g. `git`, `bundle`, or any `shipit.yml`-defined step binary). Shell/PTY command resolution against the corrupted `PATH="true"` then executes the attacker's binary as the deploy-host user.

### Impact Explanation
This is Critical: arbitrary command execution as the Shipit deploy user, achieved entirely through the attacker's own PR/fork content and a self-applied label — no privileged Shipit role, secret, or maintainer action is required. Blast radius is scoped to the attacker's own `ReviewStack`/stack (their own repository or fork with review stacks enabled), but since the deploy host and its credentials (e.g. `GITHUB_TOKEN` in `Commands#base_env`) are shared infrastructure, RCE on that host is a full compromise of the deploy environment, not merely of "their own" review stack. [9](#0-8) 

### Likelihood Explanation
Preconditions are low-cost and entirely attacker-controlled: repository must have review stacks enabled (a repository configuration the target may have chosen, e.g. for open-source contribution workflows) and an active/non-archived `ReviewStack` for the attacker's own PR. The attacker needs only the ability to open a PR and add a label to it, both permitted to any unprivileged GitHub user with fork access, and to place a maliciously-named directory in their own branch content. This is trivially repeatable against any repository that allows external PRs with review-stack provisioning.

### Recommendation
In `Shipit::Command#unbundled_env` (lib/shipit/command.rb), compute `PATH` after merging `@env`, or explicitly re-assert `PATH` last so no caller-supplied env can override it, e.g.:
```ruby
def unbundled_env
  BASE_ENV.merge(@env.stringify_keys).merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}")
end
```
Additionally, `Shipit::ReviewStack#env` should reject/blacklist reserved variable names (`PATH`, `HOME`, `BUNDLE_*`, `LD_PRELOAD`, etc.) before merging label-derived variables, and/or reuse `EnvironmentVariables#permit` with an explicit whitelist for label-derived keys.

### Proof of Concept
Minitest plan (unit-level, no live GitHub required):
```ruby
test "#unbundled_env is not overridable via injected PATH env var" do
  safe_path = "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"
  command = Shipit::Command.new('true', env: { 'PATH' => 'true' }, chdir: '.')
  assert_equal safe_path, command.unbundled_env['PATH']
end

test "ReviewStack env from a PATH-named label corrupts Command's PATH" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ['PATH']
  env = Shipit::TaskCommands.new(shipit_tasks(:shipit_restart).tap { |t| t.stack = stack }).env
  assert_equal 'true', env['PATH']  # demonstrates corrupted value reaching Command

  command = Shipit::Command.new('true', env:, chdir: '.')
  refute_equal "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}", command.unbundled_env['PATH']
end
```
These assert both sides of the claimed-broken equality: the intended `PATH` (`Shipit.shell_paths`-derived) versus the actual `PATH` reaching `PTY.spawn` after a `PATH`-named label is captured.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L41-102)
```ruby
          def process
            return unless capture_labels?

            capture_labels

            stack
          end

          private

          def capture_labels?
            opened_active_stack? ||
              labeled_active_stack? ||
              unlabeled_active_stack? ||
              reopened_active_stack?
          end

          def opened_active_stack?
            opened? && stack.present?
          end

          def labeled_active_stack?
            labeled? && stack.present? && !stack.archived?
          end

          def unlabeled_active_stack?
            unlabeled? && stack.present? && !stack.archived?
          end

          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
          end

          def opened?
            action == "opened"
          end

          def labeled?
            action == "labeled"
          end

          def unlabeled?
            action == "unlabeled"
          end

          def reopened?
            action == "reopened"
          end

          def action
            params.action
          end

          def pull_request
            params.pull_request
          end

          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/label_capturing_handler_test.rb (L122-130)
```ruby
          test "accepts extended unicode characters (emoji) in label names" do
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] = [{ "name" => "Shipit 🚢" }]
            stack = create_stack

            LabelCapturingHandler.new(payload).process

            assert_has_label stack, "Shipit 🚢"
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

**File:** test/models/shipit/review_stack_test.rb (L59-65)
```ruby
    test "#env includes the stack's pull request labels" do
      stack = shipit_stacks(:review_stack)
      stack.pull_request.labels = ["wip", "bug"]

      assert_equal stack.env["WIP"], "true"
      assert_equal stack.env["BUG"], "true"
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```

**File:** lib/shipit/commands.rb (L37-50)
```ruby
    def base_env
      @base_env ||= begin
        env = Shipit.env.merge(
          'GITHUB_DOMAIN' => github.domain,
          'GITHUB_TOKEN' => github.token
        )

        if Shipit.use_git_askpass?
          env['GIT_ASKPASS'] = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s
        end

        env
      end
    end
```
