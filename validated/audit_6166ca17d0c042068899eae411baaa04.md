### Title
Attacker-controlled PR labels (e.g. `LD_PRELOAD`, `PATH`) are injected unsanitized into deploy-host process environment via `ReviewStack#env` → `Command#unbundled_env` → `PTY.spawn` - (`app/models/shipit/review_stack.rb`, `lib/shipit/task_commands.rb`, `lib/shipit/command.rb`)

### Summary
`ReviewStack#env` converts every GitHub PR label into an environment variable named after the upcased label with value `"true"`, with no name whitelist or blacklist. That hash flows unchanged through `TaskCommands#env` and `Command#unbundled_env` into `PTY.spawn`, so an attacker who can label their own PR (e.g. `ld_preload`, `path`) can inject dangerous variable names like `LD_PRELOAD` or `PATH` into every subsequent `git`/`bundle`/`cap` invocation for that stack.

### Finding Description
Binding claimed to hold: `keys(Command#unbundled_env's @env) == keys(Shipit.env) ∪ keys(deploy_spec.machine_env) ∪ keys(@task.env)`.

Tracing the actual code shows this is false:
- `ReviewStack#env` merges arbitrary, attacker-supplied label names into the stack's env hash: `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` [1](#0-0) .
- `LabelCapturingHandler#capture_labels` writes `params.pull_request.labels.map(&:name)` verbatim (no filtering) into `PullRequest#labels` for any `opened`/`labeled`/`unlabeled`/`reopened` event on a stack that is present and not archived [2](#0-1) .
- `TaskCommands#env` merges `@stack.env` (which is `ReviewStack#env` for review stacks) into the final env hash, alongside `Shipit.env`, hardcoded vars, `deploy_spec.machine_env`, and `@task.env`: `super.merge(@stack.env).merge({...}).merge(deploy_spec.machine_env).merge(@task.env)` [3](#0-2) . This confirms a fourth, unaccounted-for source of keys — the binding is broken.
- This merged hash is passed as `env:` into `Command.new`, stored as `@env` [4](#0-3) .
- `Command#unbundled_env` does `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` — `@env` (attacker-influenced) is merged last, so it wins over `BASE_ENV`'s and the hardcoded `PATH` [5](#0-4) .
- `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [6](#0-5) , so the injected variable is present in the actual spawned child process for every git/bundle/cap invocation belonging to that stack.
- `EnvironmentVariables#permit`, the only whitelist mechanism in the codebase, is never invoked on this path — it is a private `sanitize_env_vars` helper only used by call sites that explicitly opt in (e.g. deploy variables), not by `TaskCommands#env` or `Command#unbundled_env` [7](#0-6) .
- Existing tests already demonstrate arbitrary label capture is unsanitized and reaches the final command env: `TaskCommandsTest#env includes a ReviewStack's pull request labels` asserts `env["WIP"] == "true"` for a label `"wip"` [8](#0-7) , and `ReviewStackTest` shows the same for `stack.env` directly [9](#0-8) .

Exploit flow: attacker opens a PR against a repository with `review_stacks_enabled` (provisioning behavior `allow_all`, or satisfies `allow_with_label`/`prevent_with_label`), adds the label `ld_preload` (or `path`) to their own PR via the normal GitHub UI/API. GitHub sends a legitimately-signed `pull_request` `labeled` webhook (no attacker secret needed — it's GitHub's own signature) which `LabelCapturingHandler` processes, storing `LD_PRELOAD` into `pull_request.labels`. Any subsequent task run on that review stack (a scheduled `ContinuousDeliveryJob#perform` → `stack.trigger_continuous_delivery` if `continuous_deployment: true`, or any manually-triggered task/restart/rollback) causes `TaskCommands#env` to include `LD_PRELOAD=true` in the env passed to every `git`, `bundle`, `cap` command executed for that task.

Existing guards inspected and found not to intervene: `verify_signature`/`GitHubApp#verify_webhook_signature` only validate that the request came from GitHub for that repo — they do not restrict label content. `capture_labels?` only gates which PR *events* trigger capture, not label *names*. No `Repository`/`Stack`/`PullRequest` model validation restricts label characters or reserved names. `EnvironmentVariables#permit` is not applied on this path.

### Impact Explanation
An attacker gains injection of an arbitrary-named environment variable (attack surface limited to label-name-derived keys, always with value `"true"`) into every child process (`git`, `bundle`, `cap`, custom task scripts) spawned for their review stack's deploy host. Setting `LD_PRELOAD=true` or `PATH=true` corrupts the environment of the deploy host process for that stack's execution and, combined with control over the repository's checked-out working directory contents (attacker's own branch/commit), can influence how those child binaries resolve libraries or executables — a path toward code execution under the Shipit worker's OS user. Because the same deploy host/worker process typically executes tasks for multiple stacks/repositories and holds `GITHUB_TOKEN` and other secrets in its environment (exposed via `Commands#base_env`), a compromise here has cross-tenant blast radius, matching the Critical category (RCE on the deploy host via `Command`/`PTY.spawn`).

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled` and a provisioning behavior that lets the attacker's own PR create/keep a review stack (`allow_all` requires nothing extra; `allow_with_label`/`prevent_with_label` require knowing/using the configured provisioning label, which is visible in repository settings). The attacker needs no Shipit credentials — only the ability to label their own PR, which is granted by the question's threat model. Cost is a single GitHub label action; it is fully repeatable and requires no timing or race conditions. The only uncertainty is the downstream `LD_PRELOAD`/dynamic-linker mechanics needed to reach full RCE (whether an attacker-supplied relative-path shared object in the working directory would actually be resolved by `ld.so` for a bare filename); the vulnerability itself — unsanitized attacker-controlled data reaching the process environment of spawned children — is confirmed and reproducible regardless of that downstream detail.

### Recommendation
Sanitize/whitelist label-derived environment variable names in `ReviewStack#env` before merging (e.g., reject reserved/dangerous names such as `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `BUNDLE_*`, `IFS`, etc., or use an explicit allowlist of permitted label-derived variable names). Alternatively, prefix all label-derived variables (e.g. `LABEL_LD_PRELOAD`) so they can never collide with security-sensitive variable names, and apply `EnvironmentVariables#permit` with an explicit safe-list to the final env hash before it is handed to `Command.new`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb
test "#env does not allow labels to inject dangerous variable names" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["ld_preload"]

  env = stack.env

  assert_nil env["LD_PRELOAD"], "attacker-controlled label must not set LD_PRELOAD"
end

# test/lib/shipit/task_commands_test.rb
test "#env does not propagate label-derived LD_PRELOAD/PATH to spawned commands" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["ld_preload", "path"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env
  command = Shipit::Command.new("true", env: env, chdir: ".")

  assert_nil env["LD_PRELOAD"]
  refute_equal "true", command.unbundled_env["PATH"]
end
```
Both assertions currently fail against the existing implementation (`env["LD_PRELOAD"] == "true"`, `command.unbundled_env["PATH"] == "true"`), demonstrating the broken binding.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
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

**File:** lib/shipit/environment_variables.rb (L13-44)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end

    def interpolate(argument)
      return argument unless @env

      argument.gsub(/(\$\w+)/) do |variable|
        variable.sub!('$', '')
        Shellwords.escape(@env.fetch(variable) { ENV[variable] })
      end
    end

    private

    def initialize(env)
      @env = env
    end

    def sanitize_env_vars(variable_definitions)
      allowed_variables = variable_definitions.map(&:name)

      allowed, disallowed = @env.partition { |k, _| allowed_variables.include?(k) }.map(&:to_h)

      error_message = "Variables #{disallowed.keys.to_sentence} have not been whitelisted"
      raise NotPermitted, error_message unless disallowed.empty?

      allowed
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
