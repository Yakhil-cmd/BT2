Confirmed: `PullRequest#labels` stores raw GitHub label names with no format validation, no character filter, and no whitelist check (unlike deploy/rollback/task env overrides, which go through `EnvironmentVariables#permit`). This confirms the finding.

### Title
Attacker-controlled PR labels are merged unfiltered into `ReviewStack#env`, allowing arbitrary env-var injection (`BUNDLE_GEMFILE`) into `bundle install`/`bundle exec` on the deploy host - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` upcases every GitHub PR label name and merges it directly into the stack environment with no whitelist or character filtering, unlike every other env-injection path in the engine which is gated by `EnvironmentVariables#permit`. This env hash is merged into `TaskCommands#env`, passed to `Command`, and ultimately handed unmodified to `PTY.spawn`, letting a PR author who can label their own PR inject arbitrary environment variable names (fixed value `"true"`) into every step of `deploy_spec.dependencies_steps`/`deploy_steps`, including `bundle install`.

### Finding Description
Broken binding: the value of `BUNDLE_GEMFILE` passed to `PTY.spawn` should equal the path implied by the repository's own `Gemfile`/deploy_spec (i.e. unset, or whatever `deploy_spec` explicitly configures), not an attacker-chosen key derived from a PR label. In practice, `ENV['BUNDLE_GEMFILE'] (as spawned) == 'true' (attacker label)`, which is `!=` the intended `unset/Gemfile path` value.

Code path:
- `ReviewStack#env` upcases every `pull_request.labels` entry and merges it into the stack env with value `"true"`, with zero filtering: [1](#0-0) 
- Labels are populated straight from the GitHub webhook payload, `github_pull_request.labels.map(&:name)`, and are stored via a plain serialized array column with no format validator: [2](#0-1) [3](#0-2) 
- `LabelCapturingHandler#capture_labels` writes these labels onto the `PullRequest` in response to `opened`/`labeled`/`unlabeled`/`reopened` webhook events, with the params schema only requiring `labels[].name` to be a `String` (no length/charset constraint): [4](#0-3) [5](#0-4) 
- `TaskCommands#env` unconditionally merges `@stack.env` (which is `ReviewStack#env` for review stacks) into the command environment used for every step, including `install_dependencies`: [6](#0-5) [7](#0-6) 
- `Command#unbundled_env` merges `@env` (already containing the attacker's key) last, so it wins over `BASE_ENV`/`PATH`, and is passed directly to `PTY.spawn`: [8](#0-7) [9](#0-8) 
- `deploy_spec.dependencies_steps!`/`discover_bundler`/`bundle_install` produce the `bundle install ...` command line that this env is attached to whenever a `Gemfile` exists in the checked-out working directory: [10](#0-9) 

Every other path that lets a caller inject environment variables into a task/deploy/rollback (API `env` params, `Stack#trigger_task`, `Stack#build_deploy`) is explicitly sanitized through `EnvironmentVariables#permit`, which raises `NotPermitted` for any key not declared in `deploy_variables`/`rollback_variables`/task `variables`: [11](#0-10) [12](#0-11) [13](#0-12) . `ReviewStack#env` is the one place that bypasses this filter entirely, so `capture_labels?`/`params` validation and `EnvironmentVariables#permit` do not prevent the divergence.

Exploit flow: an attacker opens a PR against a repository tracked by Shipit as a review stack, labels the PR (e.g. with a label literally named `bundle_gemfile`, case-insensitive because it's upcased), and also commits a file named exactly `true` at the repository root containing arbitrary Ruby (Gemfiles are executed as a Ruby DSL). GitHub emits the `pull_request` webhook (signed with the target repo's already-configured secret, independent of the attacker's privileges), `LabelCapturingHandler` persists the label, `ReviewStack#env` turns it into `BUNDLE_GEMFILE=true`, and when Shipit runs the review stack's `dependencies_steps` (`bundle install ...`) with `chdir` set to the PR's checked-out working directory, Bundler resolves the relative `BUNDLE_GEMFILE=true` against that directory and evaluates the attacker's `true` file as the Gemfile - arbitrary Ruby execution on the deploy host.

### Impact Explanation
This is Critical: RCE on the deploy host via `Command`/`PTY.spawn`. The attacker's arbitrary Ruby code inside the fake `true` "Gemfile" executes with the privileges of the Shipit deploy worker during `bundle install`, giving the attacker code execution outside any sandbox for the label-carrying stack. This is repeatable against any repository the attacker can open a labeled PR against and that is configured with review stacks and Bundler-based dependency detection; each PR/label event re-triggers the same env injection, so it is fully repeatable, though scoped to that stack/repository's deploy host rather than cross-tenant.

### Likelihood Explanation
Preconditions: the target repository must be configured as a Shipit review stack, must use Bundler (`Gemfile` present so `bundler?` is true), and the attacker must be able to both open a PR and apply a label to it (per the stated attacker model, this is assumed possible for their own PR). Attacker cost is low - no secrets, tokens, or elevated GitHub role are required beyond what the threat model grants. The only moving part beyond the label is committing an oddly named file (`true`) to the PR branch, which is trivial. This is easily repeatable and does not depend on race conditions or timing.

### Recommendation
Sanitize `ReviewStack#env` the same way every other env-injection surface is sanitized: run captured labels through `EnvironmentVariables#permit` against an explicit allow-list (e.g. `deploy_spec` "review label variables"), reject labels that don't map to a declared variable, and/or prefix all label-derived keys with a fixed, non-colliding namespace (e.g. `SHIPIT_LABEL_<NAME>`) instead of using the raw upcased label as the literal env var key.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_env_test.rb
require 'test_helper'

module Shipit
  class ReviewStackEnvInjectionTest < ActiveSupport::TestCase
    test 'attacker-controlled PR label injects BUNDLE_GEMFILE into task env reaching bundle install command' do
      stack = shipit_review_stacks(:some_review_stack) # a ReviewStack fixture with a Gemfile in its checkout
      stack.pull_request.update!(labels: ['bundle_gemfile'])

      task = stack.tasks.create!(user: shipit_users(:walrus), definition: stack.find_task_definition(:deploy_env))
      commands = Shipit::TaskCommands.new(task)

      # Binding under test: env reaching PTY.spawn should NOT contain an attacker-derived BUNDLE_GEMFILE
      assert_equal 'true', commands.env['BUNDLE_GEMFILE'], 'label was merged unfiltered into stack env'

      install_command = commands.install_dependencies.detect { |c| c.args.join(' ').include?('bundle install') }
      assert install_command
      assert_equal 'true', install_command.env['BUNDLE_GEMFILE'],
        'attacker label reaches the exact env hash passed to PTY.spawn for bundle install'
    end
  end
end
```
This demonstrates the broken binding: `install_command.env['BUNDLE_GEMFILE']` (attacker value `'true'`) is present and would be forwarded to `PTY.spawn`, diverging from the intended value (unset/the deploy spec's own configuration), with no `EnvironmentVariables#permit` check intervening.

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

**File:** app/models/shipit/pull_request.rb (L14-14)
```ruby
    serialize :labels, coder: Shipit.serialized_column(:labels, type: Array)
```

**File:** app/models/shipit/pull_request.rb (L48-48)
```ruby
      self.labels = github_pull_request.labels.map(&:name)
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L29-31)
```ruby
              requires :labels, Array do
                requires :name, String
              end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
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

**File:** lib/shipit/command.rb (L92-92)
```ruby
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** app/models/shipit/deploy_spec/bundler_discovery.rb (L8-37)
```ruby
      def discover_dependencies_steps
        discover_bundler || super
      end

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

**File:** lib/shipit/environment_variables.rb (L35-44)
```ruby
    def sanitize_env_vars(variable_definitions)
      allowed_variables = variable_definitions.map(&:name)

      allowed, disallowed = @env.partition { |k, _| allowed_variables.include?(k) }.map(&:to_h)

      error_message = "Variables #{disallowed.keys.to_sentence} have not been whitelisted"
      raise NotPermitted, error_message unless disallowed.empty?

      allowed
    end
```

**File:** app/models/shipit/stack.rb (L174-180)
```ruby
    def trigger_deploy(*args, **kwargs)
      if changed?
        # If this is the first deploy since the spec changed it's possible the record will be dirty here, meaning we
        # cant lock. In this one case persist the changes, otherwise log a warning and let the lock raise, so we
        # can debug what's going on here. We don't expect anything other than the deploy spec to dirty the model
        # instance, because of how that field is serialised.
        if changes.keys == ['cached_deploy_spec']
```

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
    end
```
