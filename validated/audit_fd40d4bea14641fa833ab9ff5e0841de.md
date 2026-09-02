### Title
Fork PR label name propagates into `Command#unbundled_env`'s `PATH`, letting an attacker override command resolution during `tasks.<name>.steps` execution - (File: `app/models/shipit/review_stack.rb`, `lib/shipit/command.rb`)

### Summary
`ReviewStack#env` merges every pull request label name, upcased, directly as an environment-variable key with no allowlist, so a PR labeled `path` injects a `PATH` key into the stack env. `Command#unbundled_env` merges the caller-supplied `@env` *after* it computes the safe `PATH`, so this attacker-supplied `PATH` key silently overrides the safe value before `PTY.spawn` runs the step.

### Finding Description
The broken binding: for any custom task step spawned via `Command`, the invariant should be `Command#unbundled_env['PATH'] == "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"` regardless of PR content. Instead, because `@env` can carry a fork-controlled `PATH` key, the actual binding is `Command#unbundled_env['PATH'] == @env['PATH']` whenever `@env` contains that key [1](#0-0) .

Path to the vulnerable merge:
- `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` on top of `Stack#env`, with no key allowlist [2](#0-1) .
- `LabelCapturingHandler#capture_labels` writes `params.pull_request.labels.map(&:name)` straight from the unauthenticated webhook payload into `pull_request.labels`, with only a schema-shape check (string), no name restriction [3](#0-2) .
- `TaskCommands#env` merges `@stack.env` (which for a `ReviewStack` includes the label-derived keys) into the command environment used for `tasks.<name>.steps`, and this env reaches `Command.new(command_line, env:, chdir: steps_directory)` unfiltered [4](#0-3) .
- `Command#unbundled_env` computes the intended safe `PATH` and then merges `@env.stringify_keys` on top of it, so any `PATH` key present in the task/deploy env wins: `BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)` [1](#0-0) .

Exploit flow: an unprivileged attacker opens a PR from their fork against a repository configured with `provisioning_behavior: allow_all`. The review stack checks out the attacker's own branch, so the attacker also fully controls the `shipit.yml`'s `tasks.<name>.steps` (bare command names such as `cap`, `bundle`, etc.) and the working tree content used as `chdir`. The attacker labels the PR `path` (case-insensitive; upcased to `PATH`), which `LabelCapturingHandler` persists onto `pull_request.labels`. When a `tasks.<name>.steps` command line is run, `ReviewStack#env` sets `PATH => "true"`. Since `unbundled_env` merges this last, the process's actual `PATH` becomes the literal string `"true"` — interpreted as a single, `chdir`-relative directory named `true`. The attacker also commits a subdirectory literally named `true` inside their fork containing an executable file matching the bare command name referenced by the step (e.g. a fake `cap`). When the step's checked-out `chdir` is the fork's working tree, the shell resolves the bare command via the (attacker-controlled) `PATH="true"`, executing the attacker's binary on the Shipit deploy host.

Existing guards do not stop this: `EnvironmentVariables#permit` (`lib/shipit/environment_variables.rb`) is only invoked for `filter_deploy_envs`/`filter_rollback_envs`/task's `filter_envs`, i.e. the *explicitly user-supplied* deploy/task variables — never for `Stack#env`/`ReviewStack#env`'s built-in keys, so it never sees or rejects the label-derived `PATH` key. `LabelCapturingHandler`'s `ExplicitParameters` schema only validates the shape (`labels: Array { requires :name, String }`), not the value/content of the name. `verify_signature`/`drop_unhandled_event` only gate whether the webhook is processed at all, not what label text is legal.

### Impact Explanation
Once the malicious binary is picked up by a bare command in `tasks.<name>.steps` (or similarly through `DeployCommands#env`, which also merges `@stack.env`), the attacker executes arbitrary code on the Shipit deploy host, with access to `GITHUB_TOKEN`, deploy secrets, and the ability to affect any other repository/stack Shipit manages from that host — Critical, matching the "RCE on the deploy host via `Command`/`PTY.spawn`" impact class. It is fully repeatable: any fork PR author can trigger it whenever a review stack task/deploy step is run.

### Likelihood Explanation
Preconditions: repository must have `provisioning_behavior: allow_all` (or `allow_with_label`/etc. that still allows the PR author to control the checked-out branch and its `shipit.yml`), review stacks enabled, and at least one `tasks.<name>.steps` (or deploy step) invoking a bare command name. No Shipit credentials, GitHub App keys, or maintainer approval are required — only opening a PR from a fork and applying a self-chosen label, both actions available to any GitHub user with fork/PR permissions. This is low-cost and fully attacker-controlled, making it highly likely to be exploitable in any repo running `allow_all` review stacks.

### Recommendation
Remove label names from unfiltered inclusion in `ReviewStack#env`; either drop the feature or explicitly allowlist permitted key names (reject reserved keys like `PATH`, `LD_PRELOAD`, `BUNDLE_*`, etc.), and make `Command#unbundled_env` compute `PATH` after merging `@env`, or strip/ignore any caller-supplied `PATH` key before merging so the safe managed `PATH` cannot be overridden.

### Proof of Concept
```ruby
# test/unit/command_path_override_test.rb
require "test_helper"

class CommandPathOverrideTest < ActiveSupport::TestCase
  test "[allow_all] a PR label named PATH overrides the safe PATH used by tasks.<name>.steps" do
    stack = shipit_stacks(:review_stack)
    stack.pull_request.labels = ["path"] # attacker-controlled label name

    task = shipit_tasks(:shipit_restart)
    task.stack = stack

    env = Shipit::TaskCommands.new(task).env
    assert_equal "true", env["PATH"] # attacker-controlled key reached task env

    command = Shipit::Command.new("cap deploy:restart", env: env, chdir: task.working_directory)
    resolved_path = command.unbundled_env["PATH"]

    # Broken invariant: resolved PATH is attacker-controlled ("true"),
    # not Shipit's safe computed PATH.
    assert_equal "true", resolved_path
    refute_includes resolved_path, Shipit.shell_paths.first
  end
end
```
This demonstrates the equality-under-test fails: `Command#unbundled_env['PATH']` should always equal Shipit's computed safe path but instead equals the fork-controlled label-derived value.

### Citations

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** lib/shipit/task_commands.rb (L23-48)
```ruby
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
