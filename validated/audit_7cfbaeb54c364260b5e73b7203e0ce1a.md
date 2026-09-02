### Title
Unprivileged PR label names become arbitrary env-var keys (e.g. `PERL5LIB`) reaching `PTY.spawn` via `ReviewStack#env` → `TaskCommands#env` → `Command#unbundled_env` - (File: `app/models/shipit/review_stack.rb`, `lib/shipit/task_commands.rb`, `lib/shipit/command.rb`)

### Summary
`ReviewStack#env` builds environment entries directly from GitHub pull-request label names, uppercasing them as keys and setting value `"true"`, with no allowlist of key names. `LabelCapturingHandler#capture_labels` persists these label names verbatim from the webhook payload. Those labels flow through `TaskCommands#env` into `Command`, whose `unbundled_env` merges `@env` over `BASE_ENV` unconditionally, and are handed to `PTY.spawn`, letting a fork PR author inject env-loader variables such as `PERL5LIB`.

### Finding Description
The broken binding: the set of keys reaching `PTY.spawn` is claimed to be restricted to `deploy_spec.machine_env` and declared `VariableDefinition` names, but in fact `env_keys(PTY.spawn) ⊇ pull_request.labels.map(&:upcase)` with no filtering.

Path:
1. An unprivileged attacker opens/labels a PR on their own fork with a label literally named `perl5lib` (or any case, since it is upcased) and value irrelevant (labels have no value, just a name).
2. `LabelCapturingHandler#capture_labels` in `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102` does `pull_request.update!(labels: params.pull_request.labels.map(&:name))` — the schema only requires `labels` to be an Array of Strings (`requires :labels, Array do requires :name, String end`), with no character/format restriction, so `perl5lib` is stored as-is on `Shipit::PullRequest#labels` (`app/models/shipit/pull_request.rb:14`).
3. `ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`) does:
   ```ruby
   super.merge(pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" })
   ```
   No allowlist of keys — any label name becomes an environment variable KEY.
4. `TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`) does `super.merge(@stack.env).merge(...).merge(deploy_spec.machine_env).merge(@task.env)` — `@stack.env`'s attacker-controlled keys pass straight through unless a later merge (`deploy_spec.machine_env` or `@task.env`) happens to redefine the exact same key, which an attacker does not need since `PERL5LIB` is not part of any built-in Shipit env key.
5. `TaskCommands#install_dependencies` (`lib/shipit/task_commands.rb:17-21`) builds `Command.new(command_line, env:, chdir: steps_directory)` for the deploy spec's dependency steps (e.g. `bundle install`), a `ruby`/`bundle` toolchain invocation.
6. `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) does `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` — again no key filtering; the attacker's `PERL5LIB` key survives into the final env hash.
7. `Command#start` (`lib/shipit/command.rb:85-101`) calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`, so the subprocess (the `ruby`/`bundle` dependency install step) inherits `PERL5LIB` set to `"true"` — though the observable PoC value is fixed to the literal string `"true"` (not attacker-chosen content), since `ReviewStack#env` hardcodes the value.

The `EnvironmentVariables#permit` allowlist mechanism (`lib/shipit/environment_variables.rb:13-18`) exists in the codebase, but it is never invoked in the `TaskCommands#env` / `Command#unbundled_env` path — it is a separate, unused-here whitelist utility, so it provides no protection for this flow.

Why existing guards fail: `capture_labels?`/`opened_active_stack?` etc. only gate *when* labels are captured (must be an active, non-archived stack), not *what* label names are permitted; there is no `Repository`, `Stack`, or `PullRequest` validation restricting label name characters or reserved env-var names; `deploy_spec.machine_env` and `VariableDefinition` allowlisting apply only to variables declared in the deploy spec, not to the label-derived keys merged from `@stack.env`.

### Impact Explanation
This lets any fork PR author (no repo write access needed beyond opening a PR against a repository with review stacks enabled) inject arbitrary-named environment variables — including sensitive loader variables like `PERL5LIB`, `RUBYOPT`, `BUNDLE_GEMFILE`, etc. — into the environment of Shipit's `ruby`/`bundle` dependency-install command executed via `PTY.spawn` on the deploy host. Because the value is a fixed `"true"` string set by `ReviewStack#env`, the practical exploit value depends on what a loader variable does when set to `"true"` (e.g., `RUBYOPT=true` would break execution rather than execute code; `PERL5LIB=true` just adds a bogus include path) — meaning the "PERL5LIB path traversal to RCE" claim in the question requires an attacker-chosen *value*, not just a fixed `"true"`. The mechanism (uncontrolled key injection into subprocess env) is real, but the specific RCE payload described (arbitrary value in `PERL5LIB`) is not achievable through this code path since the value is hardcoded to `"true"` by `ReviewStack#env`, not attacker-controlled.

### Likelihood Explanation
Requires: the target repository has `review_stacks_enabled` and a `ReviewStack` is provisioned for the attacker's PR (via `allow_all`, `allow_with_label`, or `prevent_with_label` behavior reachable by an unprivileged PR author), and the dependency-install step invokes a `ruby`/`bundle` tool that is sensitive to a boolean-valued `PERL5LIB` (unlikely to yield RCE as `"true"` is not a usable value for such a payload).

### Recommendation
Enforce an allowlist in `ReviewStack#env` (or centrally in `Commands#env`/`Command#unbundled_env`) restricting which keys can be set from pull-request labels — e.g. only permit label names matching a Shipit-defined prefix (such as `LABEL_<NAME>`), and/or route label-derived env through `EnvironmentVariables#permit` against the deploy spec's declared `VariableDefinition`s before merging into the process environment. At minimum, block loader/interpreter env var names (`PERL5LIB`, `RUBYOPT`, `LD_PRELOAD`, `BUNDLE_GEMFILE`, `GEM_PATH`, etc.).

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (illustrative)
test "#env allows label names to inject arbitrary env keys" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["perl5lib"]
  assert_equal "true", stack.env["PERL5LIB"]
end

# test/lib/shipit/task_commands_test.rb (illustrative)
test "#install_dependencies inherits label-derived keys via Command#unbundled_env" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["perl5lib"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  commands = Shipit::TaskCommands.new(task)
  command = commands.install_dependencies.first
  assert_equal "true", command.env["PERL5LIB"]
  assert_equal "true", command.unbundled_env["PERL5LIB"]
end
```
Both assertions pass against current code, demonstrating the key-injection mechanism is real; however, because `ReviewStack#env` hardcodes the value to `"true"`, the described RCE via attacker-chosen `PERL5LIB` *value* is not demonstrable through this path — only the fixed string `"true"` reaches the subprocess environment. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```
