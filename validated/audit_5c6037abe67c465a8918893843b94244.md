### Title
Fork-controllable PR label name injects arbitrary environment variable keys (e.g. `BUNDLE_GEMFILE`) into `ruby`/`bundle` dependency steps, enabling RCE on the deploy host - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) directly into the process environment used to run `TaskCommands#install_dependencies`, with no allowlist. Because label capture in `LabelCapturingHandler` is independent of `provisioning_behavior`, an attacker on a `prevent_with_label` repository can still label their own (non-archived) PR to inject a `BUNDLE_GEMFILE` key, which combined with an attacker-supplied file in their own PR branch causes Bundler to load and execute arbitrary Ruby code during `bundle install` on the Shipit deploy host.

### Finding Description
The broken binding: the set of keys reaching the `bundle install` subprocess env should equal a bounded, operator-controlled set (`Shipit.env` + deploy-spec `machine_env` + fixed task metadata + user-permitted `deploy_variables`/`task variables` filtered through `EnvironmentVariables#permit`). Instead:

- `ReviewStack#env` computes `super.merge(pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" })` with no key allowlist at all [1](#0-0) .
- `pull_request.labels` is populated straight from the webhook body by `LabelCapturingHandler#capture_labels`, which runs whenever the stack exists and is not archived — independent of `provisioning_behavior` (`allow_all`/`allow_with_label`/`prevent_with_label`) [2](#0-1) .
- `TaskCommands#env` merges `@stack.env` (which includes the unfiltered label-derived keys) directly into the environment passed to every `Command.new` created by `install_dependencies` [3](#0-2) .
- `Command#start` merges `@env` into `unbundled_env` and passes it straight to `PTY.spawn` [4](#0-3) .
- The bundler/ruby dependency step is `bundle install` (auto-discovered when a `Gemfile` is present) [5](#0-4) .

Exploit flow: attacker pushes a branch to their fork containing a `Gemfile` (to trigger bundler auto-discovery) plus a second file literally named `true` containing malicious Ruby (e.g. arbitrary `system(...)` calls), opens a PR against a repository configured with `provisioning_behavior: prevent_with_label`. As long as the attacker does not apply the repo's designated "prevent" label, the review stack provisions normally. The attacker then labels their own PR with a label whose uppercased form is `BUNDLE_GEMFILE` (per this exercise's stated attacker capabilities, PR authors can label their own PR). `LabelCapturingHandler` persists this label unconditionally (`labeled_active_stack?` only checks `!stack.archived?`, not the provisioning behavior). On the next task/deploy run for that review stack (e.g. triggered by `ContinuousDeliveryJob`/`trigger_continuous_delivery` on new CI success, or any triggered task), `TaskCommands#install_dependencies` runs `bundle install` with `BUNDLE_GEMFILE=true` in env. Bundler resolves `true` as a relative path in the checkout directory, finds the attacker's file, and evaluates it as a Gemfile — running arbitrary Ruby code as the Shipit process user.

Existing guards do not catch this: `EnvironmentVariables#permit` (used for `filter_deploy_envs`/`filter_task_envs`/`filter_rollback_envs`, i.e. user-submitted API/UI env overrides) is never applied to `ReviewStack#env`'s label-derived hash [6](#0-5) ; `verify_signature`/webhook validation only authenticates that the webhook came from GitHub for that repo, it does not restrict label content; and `provisioning_behavior` gates only archive/unarchive state transitions in `LabeledHandler`/`UnlabeledHandler`, not label capture in `LabelCapturingHandler`.

### Impact Explanation
Arbitrary command execution as the Shipit worker process on the deploy host, satisfying the Critical RCE class ("a command running that should not"). The attacker only needs push access to their own fork and PR-labeling capability on their own PR against a `prevent_with_label`-configured target repository; once triggered, the malicious `Gemfile`-equivalent file executes with the full privileges of the Shipit deploy process (which typically also holds `GITHUB_TOKEN` and other deploy secrets in env), so this also enables credential exfiltration as a secondary effect. It is repeatable against any repository using review stacks with `prevent_with_label` (or, more broadly, any review-stack repo, since label capture is not gated by provisioning behavior at all).

### Likelihood Explanation
Preconditions: target repository must have `review_stacks_enabled` with `provisioning_behavior` set (the question scopes to `prevent_with_label`, though the underlying capture bug is not specific to it), and Bundler auto-discovery must apply (a `Gemfile` present in the PR branch). Attacker cost is low: push a branch, open a PR, add one label. No secrets, sessions, or maintainer privileges are required beyond the capabilities explicitly granted to PR authors in this exercise (opening a PR, pushing to a fork, labeling their own PR). This is straightforward to reproduce repeatedly and automate.

### Recommendation
Do not merge raw, attacker-controlled label names as environment variable keys. `ReviewStack#env` should either drop the label-to-env feature entirely, or route it through an explicit allowlist (analogous to `EnvironmentVariables#permit`) restricted to a safe, prefixed namespace (e.g. only accept labels matching `^SHIPIT_LABEL_[A-Z0-9_]+$` and reject/ignore anything that collides with sensitive names like `BUNDLE_*`, `RUBYOPT`, `GEM_*`, `PATH`, `LD_PRELOAD`, etc.), and always sanitize keys server-side (e.g., strip characters outside `[A-Z0-9_]` and reject reserved/toolchain variable names) before merging into any `Command` env.

### Proof of Concept
minitest plan (in `test/models/shipit/review_stack_test.rb` or `test/lib/shipit/task_commands_test.rb` style, no live GitHub required):
```ruby
test "#env lets a PR label inject BUNDLE_GEMFILE into install_dependencies env" do
  stack = shipit_stacks(:review_stack)
  stack.update!(provisioning_behavior: :prevent_with_label, provisioning_label_name: "shipit-prevent")
  stack.pull_request.labels = ["bundle_gemfile"] # attacker-chosen label, no allowlist applied

  task = shipit_tasks(:shipit_restart)
  task.stack = stack
  commands = Shipit::TaskCommands.new(task)

  env = commands.env
  # Binding under test: env keys should be limited to an operator-approved allowlist,
  # i.e. env.keys.all? { |k| ALLOWED_KEYS.include?(k) } == true
  # Actual: attacker-controlled key reaches env unfiltered
  assert_equal "true", env["BUNDLE_GEMFILE"]

  install_step = commands.install_dependencies.first
  assert_equal "true", install_step.env["BUNDLE_GEMFILE"]
end
```
This demonstrates the equality `env["BUNDLE_GEMFILE"] == "true"` (attacker-controlled key present) versus the expected invariant `env.keys ⊆ allowlist` (should be false/absent), confirming the divergence without requiring any live GitHub call, matching the "prevent_with_label" scenario since label capture and `ReviewStack#env` merging are independent of `provisioning_behavior`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L62-102)
```ruby
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

**File:** lib/shipit/task_commands.rb (L17-48)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

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

**File:** app/models/shipit/deploy_spec/bundler_discovery.rb (L12-37)
```ruby
      def discover_bundler
        bundle_install if bundler?
      end

      def bundle_exec(command)
        if bundler? && dependencies_steps.include?(remove_ruby_version_from_gemfile)
          "bundle exec #{command}"
        else
          command
        end
      end

      def discover_machine_env
        super.merge('BUNDLE_PATH' => bundle_path.to_s)
      end

      def bundle_install
        install_command = %(bundle install --jobs 4 --retry 2)
        [
          remove_ruby_version_from_gemfile,
          (bundle_config_frozen if frozen_mode?),
          bundle_config_path,
          bundle_without_groups,
          install_command
        ].compact
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
