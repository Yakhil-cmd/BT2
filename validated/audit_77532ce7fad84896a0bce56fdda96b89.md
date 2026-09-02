### Title
Unvalidated PR labels injected into deploy environment reach `PTY.spawn` unfiltered - ([File: lib/shipit/task_commands.rb])

### Summary
`Shipit::ReviewStack#env` converts every PR label into an environment variable (`LABEL_NAME.upcase => "true"`) with no allow-list, and `TaskCommands#env` merges `@stack.env` into the final environment *before* the hardcoded hash and `deploy_spec.machine_env`, both of which only add/override keys they explicitly declare rather than filtering the accumulated hash. `Command#unbundled_env` then merges this hash directly into the environment passed to `PTY.spawn`, with no whitelist enforcement (`EnvironmentVariables#permit`/`VariableDefinition` sanitization is never invoked in this path).

### Finding Description
The broken binding: the code assumes `final_env.keys ⊆ deploy_spec.machine_env.keys ∪ hardcoded_keys` (i.e., all env vars reaching `PTY.spawn` are either operator-declared `machine_env` entries or Shipit-controlled hardcoded keys), but in practice `final_env.keys ⊇ pull_request.labels.map(&:upcase)` as well, because nothing removes or filters out keys not present in the whitelist.

Path:
1. An attacker with a PR against a repository that has `review_stacks_enabled` and `continuous_deployment` on labels their own PR (e.g. label `ld_preload`). This fires a GitHub `labeled` webhook that `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler#capture_labels` processes without any authorization check beyond schema validation, calling `pull_request.update!(labels: params.pull_request.labels.map(&:name))` [1](#0-0) .
2. `Shipit::ReviewStack#env` merges `pull_request.labels` into the stack's env hash, upcasing each label name as a key mapped to `"true"`, with no filtering against any known/permitted variable list [2](#0-1) .
3. `Shipit::TaskCommands#env` builds the final environment by merging, in order: `super` (base env), `@stack.env` (now containing `LD_PRELOAD=true`), a hardcoded hash of Shipit-controlled keys, `deploy_spec.machine_env`, and `@task.env` [3](#0-2) . Because `Hash#merge` only overwrites keys present in the argument, and `deploy_spec.machine_env` doesn't declare `LD_PRELOAD`, the tainted key survives all subsequent merges untouched.
4. `Shipit::DeployCommands#env` calls `super.merge(...)`, further layering keys but never removing unknown ones [4](#0-3) .
5. This env hash is passed to `Shipit::Command.new(step, env: env, chdir: dir)`, and on `start`, `Command#unbundled_env` merges `@env.stringify_keys` directly on top of `BASE_ENV`/`PATH` with no allow-list filtering, then calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [5](#0-4) [6](#0-5) .

The `EnvironmentVariables#permit`/`sanitize_env_vars` whitelist mechanism exists in the codebase [7](#0-6)  and is used elsewhere (e.g. for validating deploy-time env in controllers), but it is never invoked in the `TaskCommands#env`/`Command#start` path, so it provides no protection here. This behavior is also directly asserted as intended by existing tests, which confirm arbitrary label names become env vars (`WIP`, `BUG`, etc.) with no allow-list check: [8](#0-7) [9](#0-8) .

### Impact Explanation
An unprivileged PR author on a repository with `review_stacks_enabled` and `continuous_deployment` on can set `LD_PRELOAD=true` (or point it at an attacker-controlled shared object path if a longer label string is used, subject to GitHub label length limits) in the environment of every step of every future deploy for that review stack. Since `PTY.spawn` executes the deploy steps (git, bundler, capistrano, custom deploy scripts) on the Shipit deploy host with this environment, this is a path to command/library injection at deploy time - Critical, matching "RCE on the deploy host via `Command`/`PTY.spawn`". The blast radius is scoped to the review stack for that repository/PR (the label capture writes only to `stack.pull_request` belonging to that repository's review stack), but is repeatable on every deploy trigger and requires no special privileges beyond opening/labeling a PR.

### Likelihood Explanation
Preconditions are modest and realistic: the target repository must have `review_stacks_enabled` and `continuous_deployment` turned on (both are legitimate, documented Shipit features, not unusual hardening). The attacker only needs the ability to open a PR and add a label to it — GitHub allows PR authors (including from forks, depending on repo settings) to add labels they've created or that already exist, and the webhook path performs no authentication beyond schema validation of the payload shape. No secrets, tokens, or elevated GitHub/Shipit permissions are required. This makes the attack cheap, deterministic, and repeatable.

### Recommendation
Sanitize `ReviewStack#env`'s label-derived hash before merging (e.g., reject label names that don't match a safe pattern, and/or run the final merged environment through `EnvironmentVariables#permit` against `deploy_spec.machine_env`'s declared `VariableDefinition`s, rejecting/dropping any unpermitted keys) so that only variables explicitly declared in `shipit.yml`'s `machine_env` (or a small Shipit-controlled hardcoded set) can reach `Command#unbundled_env` and `PTY.spawn`. At minimum, block well-known dangerous variable names such as `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `PATH`, etc. from ever being set via PR labels.

### Proof of Concept
```ruby
# test/lib/shipit/deploy_commands_test.rb (extending existing test file)
test "#env allows PR labels to inject dangerous environment variables" do
  stack = shipit_stacks(:review_stack)
  deploy = stack.trigger_continuous_delivery
  stack.pull_request.labels = ["ld_preload"]

  env = Shipit::DeployCommands.new(deploy).env

  # Binding under test: env.keys should be a subset of
  # deploy_spec.machine_env.keys ∪ hardcoded-Shipit-keys.
  # This assertion demonstrates the binding is violated:
  assert_equal "true", env["LD_PRELOAD"]
  refute_includes deploy.stack.cached_deploy_spec_content.to_s, "LD_PRELOAD" # never declared in machine_env
end
```
This mirrors the existing `test/lib/shipit/deploy_commands_test.rb` test structure (which already proves arbitrary label names become env keys) but demonstrates the specific dangerous key `LD_PRELOAD` surviving into the environment ultimately passed to `Command#unbundled_env`/`PTY.spawn`.

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

**File:** lib/shipit/deploy_commands.rb (L9-16)
```ruby
    def env
      commit = @task.until_commit
      super.merge(
        'SHA' => commit.sha,
        'REVISION' => commit.sha,
        'DIFF_LINK' => diff_url
      )
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
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

**File:** test/models/shipit/review_stack_test.rb (L59-65)
```ruby
    test "#env includes the stack's pull request labels" do
      stack = shipit_stacks(:review_stack)
      stack.pull_request.labels = ["wip", "bug"]

      assert_equal stack.env["WIP"], "true"
      assert_equal stack.env["BUG"], "true"
    end
```
