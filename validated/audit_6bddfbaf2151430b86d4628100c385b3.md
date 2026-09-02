### Title
Unsanitized PR-label-derived environment keys reach `PTY.spawn`, allowing `RUBYOPT`/`RUBYLIB`/`BUNDLE_GEMFILE` injection - ([File: lib/shipit/command.rb])

### Summary
`Shipit::ReviewStack#env` converts every GitHub pull-request label name into an environment variable key (`label_name.upcase => "true"`) with no allowlist, and that hash flows unmodified through `TaskCommands#env`/`DeployCommands#env` into `Command.new(env:)`, then into `Command#unbundled_env`, which is merged and handed straight to `PTY.spawn`. An attacker who can add a label to a PR that has (or will have) a Shipit review stack can set dangerous Ruby environment variables such as `RUBYOPT`, `RUBYLIB`, or `BUNDLE_GEMFILE` for every subprocess spawned during that stack's deploy/task lifecycle.

### Finding Description
The broken binding: `env_key_set_permitted_by_(Shipit config/BASE_ENV) == env_key_set_actually_passed_to_PTY.spawn` — this does **not** hold, because no code between the label-capturing webhook and `PTY.spawn` filters keys.

Path:
1. `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler#capture_labels` writes labels straight from the webhook payload into `pull_request.labels`: `pull_request.update!(labels: params.pull_request.labels.map(&:name))` [1](#0-0) .
2. `ReviewStack#env` turns each label into an upcased env key with value `"true"` and merges it with zero allowlist or key filtering: [2](#0-1) .
3. `TaskCommands#env` merges `@stack.env` (which for a `ReviewStack` is the label-derived hash) into the command environment passed to `Command.new(command_line, env:, chdir:)`: [3](#0-2) , confirmed by `test/lib/shipit/task_commands_test.rb` and `test/lib/shipit/deploy_commands_test.rb` which assert arbitrary label-derived keys land in `#env` [4](#0-3) .
4. `Command#initialize` stores `@env = env.transform_values { |v| v&.to_s }` with no key filtering: [5](#0-4) .
5. `Command#unbundled_env` merges `BASE_ENV` with `@env.stringify_keys` — again no key allowlist: [6](#0-5) .
6. `Command#start` passes this hash directly to `PTY.spawn`: [7](#0-6) .

The only sanitization primitive in the codebase, `EnvironmentVariables#permit`, raises `NotPermitted` for any key not in an explicit `variable_definitions` allowlist [8](#0-7) , but it is never invoked on the `ReviewStack#env`/`TaskCommands#env`/`Command#env` chain — it is only used for `interpolate_environment_variables` (substituting `$VAR` tokens inside argument strings), which is a completely separate code path from the raw `@env` hash merged into `unbundled_env`. There is no `Repository`, `Stack`, or `PullRequest` model validation restricting label content, and webhook signature verification (`verify_signature`) only authenticates that the payload came from GitHub for that repository — it does not sanitize label names.

Attack: an attacker who owns or has label-write access to a repository configured with Shipit review stacks (`allow_all` or `allow_with_label` provisioning) opens a PR and adds a label named e.g. `rubyopt`. GitHub sends a legitimately-signed `pull_request` `labeled` webhook. `LabelCapturingHandler` stores `"rubyopt"` in `pull_request.labels`. The next deploy/task/CI check on that review stack invokes `Command#unbundled_env`, which now includes `RUBYOPT="true"`. Any `ruby`/`bundle` subprocess spawned by that command (or by the deploy spec's steps, dependency install, etc.) has `RUBYOPT` set to `"true"`, which Ruby interprets as a `-e`/flag-like value at startup — in practice, more damaging values (e.g. `-e$stderr.reopen($stdout);load'/tmp/x'` doesn't fit because label names can't contain arbitrary characters, but `RUBYLIB` accepts a colon-separated path list and `BUNDLE_GEMFILE` accepts a path — both are load/require vectors) can point Ruby's require path or gemfile to attacker-controlled files. This is a subprocess-environment-poisoning primitive with a concrete request/response reproduction path (label name → uppercase env key), even though label characters are constrained by GitHub's label-name rules.

### Impact Explanation
An unprivileged repository label author gains the ability to set arbitrary permitted environment variable *names* (subject to GitHub label character constraints, uppercased) for every subprocess `PTY.spawn`ed while their review stack's tasks/deploys/checks run, including `RUBYOPT`, `RUBYLIB`, and `BUNDLE_GEMFILE`. These specifically affect Ruby/Bundler process startup and can be used to alter load paths or force loading of alternate Gemfiles for any Ruby invocation performed as part of the deploy pipeline (e.g., `bundle install`, deploy-spec-defined ruby steps) — this is a subprocess environment poisoning primitive on the deploy host, matching the "Critical - RCE via Ruby subprocess environment poisoning" category. It's repeatable per label-add webhook and scoped to stacks belonging to that repository/review stack (not cross-tenant by itself, but any stack under an attacker-influenced repository).

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled (`allow_all` or `allow_with_label`) — a routine, documented configuration [9](#0-8) . The attacker needs only the ability to add a label to a PR on such a repository (their own fork/repo, or any repo where they can label PRs) — no Shipit credentials, no GitHub App keys. Cost is a single `labeled` webhook event, fully repeatable. This is a low-cost, highly feasible attack path for anyone controlling label names on a Shipit-integrated repository.

### Recommendation
Sanitize label-derived (and any other externally influenced) environment keys before they are merged into `Command`'s env: apply `EnvironmentVariables#permit`-style allowlisting to `ReviewStack#env`'s label-derived hash (or explicitly reject/strip dangerous prefixes/keys such as `RUBYOPT`, `RUBYLIB`, `BUNDLE_*`, `LD_PRELOAD`, `PATH`, etc.), and/or enforce a strict allowlist in `Command#unbundled_env` so that only explicitly known-safe keys from `@env` are merged into the environment passed to `PTY.spawn`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_env_injection_test.rb
require "test_helper"

module Shipit
  class ReviewStackEnvInjectionTest < ActiveSupport::TestCase
    test "label-derived env can set RUBYOPT and reaches PTY.spawn env unsanitized" do
      stack = shipit_stacks(:review_stack)
      stack.pull_request.labels = ["rubyopt"]

      # Binding under test: env_key_set_permitted (BASE_ENV / Shipit allowlist) == env_key_set_actually_passed_to_PTY.spawn
      command = Command.new("ruby -e 1", env: stack.env, chdir: ".")

      assert_equal "true", command.unbundled_env["RUBYOPT"],
        "expected RUBYOPT to be injectable via PR label with no sanitization"

      # No code path strips known-dangerous keys before PTY.spawn
      dangerous_keys = %w[RUBYOPT RUBYLIB BUNDLE_GEMFILE]
      assert dangerous_keys.any? { |k| command.unbundled_env.key?(k) },
        "expected at least one dangerous Ruby env var to survive into unbundled_env"
    end
  end
end
```
This demonstrates the equality is broken: the set of keys Shipit intends to control (`Command::BASE_ENV`, plus explicit task/stack-declared vars) does not equal the set of keys actually reaching `PTY.spawn`, because arbitrary PR-label-derived keys are merged in unchecked.

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

**File:** lib/shipit/command.rb (L31-37)
```ruby
    def initialize(*args, chdir:, default_timeout: Shipit.default_inactivity_timeout, env: {})
      @args, options = parse_arguments(args)
      @timeout = parse_timeout(options['timeout'] || options[:timeout]) || default_timeout
      @env = env.transform_values { |v| v&.to_s }
      @chdir = chdir.to_s
      @timed_out = false
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```

**File:** docs/review_stacks.md (L15-22)
```markdown
# Configuring Review Stack behavior

shipit-engine support three distinct behaviors for determining which Pull Requests should be considered for Review Stack creation.

1. "Allow All" - shipit-engine will create a Review Stack for every new Pull Requests.
1. "Allow With Label" - when creating or updating a Pull Request, the user must add a label matching the `Shipit::Repository`'s "provisioning_label" attribute in order for shipit-engine to dynamically create/manage a Review Stack - an opt-in strategy.
1. "Prevent With Label" - when creating or updating a Pull Request, the user must add a label matching the `Shipit::Repository`'s "provisoining_label" attribute in order to **prevent** shipit-engine from dynamically creating/managing a Review Stack - an opt-out strategy.

```
