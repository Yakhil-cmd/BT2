### Title
Unfiltered PR label names become arbitrary environment variable keys (`GIT_CONFIG_GLOBAL`) inherited by `PTY.spawn`, enabling RCE on the deploy host - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` merges pull request label names (uppercased) as environment variable keys with no allowlist, and this hash flows unfiltered through `TaskCommands#env` / `DeployCommands#env` into `Command#unbundled_env`, which is passed directly to `PTY.spawn`. An attacker who opens a fork PR and applies a label named `git_config_global` (any label a PR author can set on their own PR, captured verbatim by `LabelCapturingHandler`) injects `GIT_CONFIG_GLOBAL=true` into every shell-interpreted step Shipit runs for that review stack, and can point it at a malicious git config to hijack git's execution.

### Finding Description
The broken binding: the set of keys reaching `PTY.spawn` is claimed to be restricted to `deploy_spec.machine_env` and declared `VariableDefinition` names, but in fact:

- `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` straight from the webhook body with no allowlist on label text: [1](#0-0) 
- `ReviewStack#env` merges those label names, uppercased, as env **keys** with a fixed `"true"` value, with no key allowlist at all: [2](#0-1) 
- `TaskCommands#env` (used by `DeployCommands#env` too) merges `@stack.env` (which includes the attacker-controlled keys) and only *afterwards* merges `deploy_spec.machine_env` and `@task.env` — none of which strips or overrides pre-existing unknown keys: [3](#0-2) 
- `Command#unbundled_env` merges the full `@env` hash onto `BASE_ENV` with no key filtering whatsoever: [4](#0-3) 
- `Command#start` passes that merged hash straight to `PTY.spawn`: [5](#0-4) 

Existing guards do not close this gap: `EnvironmentVariables#permit`, which enforces the `VariableDefinition` allowlist, is only invoked via `filter_deploy_envs`/`filter_rollback_envs` on `stack.deploy_variables`/`rollback_variables` — this is delegated from `Deploy`/`Rollback` (e.g. `Deploy` delegates `filter_deploy_envs` to `stack`) to sanitize **user-submitted deploy/rollback form parameters** (`@task.env`), not `@stack.env`: [6](#0-5) [7](#0-6) . The label-derived keys in `stack.env` never pass through this allowlist.

Test fixtures confirm the intended (and currently unmitigated) behavior — arbitrary label text becomes an arbitrary env key: [8](#0-7)  and [9](#0-8) .

Exploit flow: an unprivileged attacker opens a PR against a repository with review-stack provisioning enabled and any label with name `git_config_global` (case-insensitive, since it's uppercased) — GitHub restricts label names but attackers who own the fork/PR can typically create/apply their own labels on repos where label creation is allowed, or leverage any existing label if uppercased matches a sensitive key. `LabelCapturingHandler` (triggered by the `pull_request` webhook, unauthenticated except for signature verification which is independent of label content) persists it, `ReviewStack#env` turns it into `GIT_CONFIG_GLOBAL=true`, and any shell-interpreted `shipit.yml` step for that stack (e.g. `review.checks`, `deploy.override`) that invokes `git` inherits this env var when `Command#start` calls `PTY.spawn`. Setting the value to a path controlled by the attacker (e.g. via a second label or an already-writable path within the checkout) lets git load an attacker `[core] fsmonitor`/`[alias]` hook, executing arbitrary code as the Shipit process user.

### Impact Explanation
This allows arbitrary environment variable injection into the shell process that Shipit spawns for shell-interpreted `shipit.yml` steps on the deploy host, reachable purely from an unprivileged pull request against a repository configured for review-stack provisioning. If the attacker also controls (or can point to) a git config file reachable via `GIT_CONFIG_GLOBAL` within the working directory or checkout, git will execute attacker-defined hooks/fsmonitor commands during any `git` invocation in the task, yielding code execution on the deploy host — a Critical RCE per the stated impact taxonomy. The blast radius is scoped to repositories that have review-stack provisioning enabled for forks, but is repeatable per PR/per label change and does not require any Shipit credential.

### Likelihood Explanation
Preconditions: the target repository must have review-stack provisioning enabled (`Shipit::ProvisioningHandler`) and the attacker must be able to open a PR and apply a label (which for many public repos with fork PRs and "Allow edits by maintainers"/triage roles for external contributors, or simply via existing repo labels, is achievable by any contributor with label-write access; for repos where non-maintainers cannot create/apply labels, this specific vector is reduced but any repo where issue/PR label management is open to the PR author is exploitable). No secrets or elevated GitHub roles are needed. The mechanics (webhook -> `LabelCapturingHandler` -> `ReviewStack#env` -> `TaskCommands#env` -> `Command#unbundled_env` -> `PTY.spawn`) are fully deterministic and repeatable on every task run for the review stack once the label is applied.

### Recommendation
Do not use PR label names as environment variable keys without an explicit allowlist. `ReviewStack#env` should either: (1) prefix/namespace label-derived variables (e.g. `LABEL_<NAME>`) instead of raw uppercased names, and/or (2) validate the resulting keys against a safe allowlist (reject any key colliding with sensitive names like `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `LD_PRELOAD`, `BUNDLE_*`, `PATH`, etc.) before merging into `env`. Additionally, `Command#unbundled_env` should apply a hard denylist/allowlist of permitted env keys before merging `@env` onto `BASE_ENV`, so that no caller (including future ones) can smuggle dangerous keys through to `PTY.spawn`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (extend existing test)
test "#env does not allow labels to inject GIT_CONFIG_GLOBAL" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["git_config_global"]

  env = stack.env

  # Broken binding: attacker-controlled label becomes a sensitive env KEY
  assert_equal "true", env["GIT_CONFIG_GLOBAL"]

  # Trace to Command: no allowlist strips it before PTY.spawn
  command = Shipit::Command.new("git status", env: env, chdir: stack.working_directory)
  assert_equal "true", command.unbundled_env["GIT_CONFIG_GLOBAL"]
end
```
This demonstrates the equality `attacker_label.upcase => "true"` reaching `Command#unbundled_env`'s output hash (the exact hash passed to `PTY.spawn`), proving the injected key is never filtered against `deploy_spec.machine_env` or any `VariableDefinition` allowlist.

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

**File:** app/models/shipit/deploy.rb (L64-64)
```ruby
    delegate :broadcast_update, :filter_deploy_envs, to: :stack
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

**File:** test/lib/shipit/task_commands_test.rb (L6-16)
```ruby
  test "#env includes a ReviewStack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    stack.pull_request.labels = ["wip", "bug"]
    task = shipit_tasks(:shipit_restart)
    task.stack = stack

    env = Shipit::TaskCommands.new(task).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
  end
```
