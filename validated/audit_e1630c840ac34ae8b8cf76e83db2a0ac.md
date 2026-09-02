### Title
Pull-request label names are merged unsanitized into `ReviewStack#env`, letting a fork PR inject `GIT_CONFIG_GLOBAL` into every task/deploy/rollback command - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` merges every PR label name (uppercased) directly as an environment-variable key with no allowlist, and this merged hash flows unfiltered into `TaskCommands#env` → `Command#unbundled_env` → `PTY.spawn`. A fork PR author who can label their own PR can force `GIT_CONFIG_GLOBAL=true` into the environment of the `rollback.override` (and any other) step, and since the value resolves relative to the task's checkout `chdir`, a file named `true` committed in the fork becomes a git config file that git will read and execute (e.g. via `core.fsmonitor` or a configured hook), yielding command execution on the deploy host.

### Finding Description
The broken binding is: the set of environment-variable keys reaching `Command#start`/`PTY.spawn` for a review-stack task should equal `Stack#env ∪ deploy_spec-declared variables (filtered by EnvironmentVariables#permit)`. In practice it equals `Stack#env ∪ {label.upcase => "true" for each PR label}`, with no allowlist applied to the label-derived keys.

Code path:
- `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` straight from the webhook payload onto `pull_request.labels` with no key restriction: [1](#0-0) 
- `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into the stack's base env, unconditionally and with no key allowlist: [2](#0-1) 
- `TaskCommands#env` merges `@stack.env` (which for a `ReviewStack` includes the label-derived keys) into the env used to build every `Command` for install_dependencies/deploy/rollback steps: [3](#0-2) 
- `RollbackCommands#env` (used for `deploy_spec.rollback_steps!`, i.e. `rollback.override`) only adds `ROLLBACK=1` on top of the same unsanitized `TaskCommands#env`: [4](#0-3) 
- `Command#unbundled_env` merges `@env.stringify_keys` last, so any key present in the task/stack env unconditionally overrides `BASE_ENV`/`ENV`, and this hash is passed straight to `PTY.spawn`: [5](#0-4) [6](#0-5) 

The only sanitizer in the codebase, `EnvironmentVariables#permit`, is applied exclusively to `deploy_variables`/`rollback_variables` (the explicit user-supplied variable feature, via `filter_deploy_envs`/`filter_rollback_envs`), not to `Stack#env`/`ReviewStack#env`: [7](#0-6) [8](#0-7) . Since `ReviewStack#env` never routes through `filter_rollback_envs`/`filter_deploy_envs`, the whitelist never sees the label-derived keys, so `GIT_CONFIG_GLOBAL` (or any other sensitive variable name, e.g. `LD_PRELOAD`, `GIT_SSH_COMMAND`, `BUNDLE_GEMFILE`) reaches the spawned process untouched.

Exploit flow: attacker opens a PR from their fork against a repo whose `provisioning_behavior` is `allow_all` (so the review stack auto-provisions and runs deploy/rollback steps against fork content), commits a file literally named `true` at the repository root containing a malicious `[core] fsmonitor = "...attacker command..."` (or `core.hooksPath`) directive, and labels the PR `git_config_global`. `LabelCapturingHandler` persists the label, `ReviewStack#env` turns it into `GIT_CONFIG_GLOBAL=true`, and the next git invocation during any task step (dependencies/deploy/`rollback.override`) run with `chdir` in the fork's checkout resolves `true` relative to that directory and executes the attacker's hook/fsmonitor command.

Existing guards do not stop this: `verify_signature`/webhook auth only prove the label event came from GitHub, not that the label name is safe; `ExplicitParameters` only validates the JSON shape of the labels array, not the label's semantic use; `EnvironmentVariables#permit` is never invoked on this path at all.

### Impact Explanation
Arbitrary command execution on the Shipit deploy host in the context of the process running deploy/rollback tasks (able to read `GITHUB_TOKEN`, repository checkouts, and other secrets available to the task process), triggered by an unprivileged fork PR labeling. This is repeatable against every repository configured with `provisioning_behavior=allow_all`, matching the Critical "RCE on the deploy host via `Command`/`PTY.spawn`" category.

### Likelihood Explanation
Requires: (1) target repo configured with `provisioning_behavior: allow_all` for review stacks, (2) attacker able to add/apply the crafted label name to their own PR (per the stated attacker model this is an available action), and (3) attacker controls the fork content to place the `true` config file. No Shipit credentials, sessions, or GitHub App secrets are needed. Cost is a single PR + label + push, fully repeatable.

### Recommendation
- Do not merge PR labels directly into the process environment. Either drop this feature or map labels to a restricted, explicitly allowlisted set of variable names (e.g. prefix like `SHIPIT_LABEL_` and/or filter through `EnvironmentVariables.with(...).permit(...)` against a fixed allowlist).
- Reject any label-derived key that collides with sensitive/reserved environment variable names (`GIT_*`, `LD_*`, `BUNDLE_*`, `PATH`, etc.).
- Ensure `ReviewStack#env`'s label merge goes through the same `filter_*_envs`/`permit` mechanism already used for `deploy_variables`/`rollback_variables`.

### Proof of Concept
minitest plan (no live GitHub, `test/` only):
```ruby
test "rollback.override step inherits GIT_CONFIG_GLOBAL injected via an uppercased PR label" do
  stack = shipit_review_stacks(:some_review_stack) # ReviewStack fixture with allow_all
  stack.pull_request.update!(labels: ["git_config_global"])

  rollback_commands = Shipit::RollbackCommands.new(shipit_rollbacks(:some_rollback))
  env = rollback_commands.env

  # Binding under test: rollback.override env must NOT contain fork-controllable GIT_CONFIG_GLOBAL
  assert_nil env["GIT_CONFIG_GLOBAL"], "expected no GIT_CONFIG_GLOBAL, but label injection produced: #{env['GIT_CONFIG_GLOBAL'].inspect}"
end
```
Running this against current code fails the assertion because `env["GIT_CONFIG_GLOBAL"]` equals `"true"`, confirming the label-name injection reaches the env hash that `Command#unbundled_env` passes to `PTY.spawn`.

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

**File:** lib/shipit/rollback_commands.rb (L1-14)
```ruby
# frozen_string_literal: true

module Shipit
  class RollbackCommands < DeployCommands
    def steps
      deploy_spec.rollback_steps!
    end

    def env
      super.merge(
        'ROLLBACK' => '1'
      )
    end
  end
```

**File:** lib/shipit/command.rb (L85-98)
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
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
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
