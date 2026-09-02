### Title
Unrestricted pull-request-label env-key injection into `TaskCommands`/`Command#unbundled_env` allows unprivileged fork-PR authors to set arbitrary environment variable names (e.g. `GEM_HOME`) reaching `PTY.spawn` - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) into the stack environment hash with a fixed value of `"true"` and **no key allowlist**, and this raw hash flows unfiltered through `TaskCommands#env` into `Command#unbundled_env`, which is passed directly to `PTY.spawn`. An unprivileged fork PR author can therefore inject arbitrary environment variable **names** (such as `GEM_HOME`, `RUBYOPT`, `BUNDLE_GEMFILE`, etc.) into every task/deploy command run for their review stack, including `bundle install`/`ruby` dependency steps.

### Finding Description
The broken binding, stated as an equality that should hold but does not:
`keys(env passed to PTY.spawn) == keys(deploy_spec.machine_env) ∪ keys(declared VariableDefinition names)` — this is false, because `ReviewStack#env` injects arbitrary attacker-chosen keys with no allowlist.

Code path:
1. `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim from the webhook payload onto `pull_request.labels` with no filtering: [1](#0-0) 
   This handler runs for `opened`, `labeled`, `unlabeled`, and `reopened` events on any stack the attacker's own PR maps to (`capture_labels?`), requiring only that a review stack already exists for the PR (created via `allow_all`, or `allow_with_label`/`prevent_with_label` if the attacker also adds the provisioning label — all attacker-controlled since it's their own PR).

2. `ReviewStack#env` merges `labels.each_with_object({}) { |n,h| h[n.upcase] = "true" }` onto the base `Stack#env` with **no allowlist**: [2](#0-1) 
   This is confirmed as intentional/tested behavior, not filtered by any allowlist: [3](#0-2) 

3. `TaskCommands#env` merges `@stack.env` (which includes the label-derived keys) directly into the task env, with `@task.env` (the only allowlisted piece, filtered via `TaskDefinition#filter_envs`/`EnvironmentVariables#permit`) merged **on top** — meaning the allowlist only constrains attacker-supplied *task parameters*, not the keys already contributed by `@stack.env`: [4](#0-3) 
   `EnvironmentVariables#permit` is used elsewhere (deploy/task creation endpoints) to sanitize user-supplied `env` params against `VariableDefinition` names: [5](#0-4) 
   but it is never invoked on `Stack#env`/`ReviewStack#env` or on the final merged `TaskCommands#env`/`DeployCommands#env`.

4. `install_dependencies` builds a `Command` with this unfiltered `env`: [6](#0-5) 
   and `Command#unbundled_env` merges `@env.stringify_keys` onto `BASE_ENV` with **no allowlist at all**: [7](#0-6) 
   which is passed straight to `PTY.spawn`: [8](#0-7) 

5. The dependency step's working directory (`steps_directory`) is inside the attacker's own checked-out fork branch content: [9](#0-8) 
   Since the attacker fully controls their fork's file tree, they can commit a directory literally named `true` (matching the label-injected value) at the resolved location, pre-populated with a malicious gem tree (`specifications/`, `gems/`, `bin/` with executable hooks, etc.). When `GEM_HOME` is set to the relative path `"true"`, Ruby/RubyGems/Bundler resolve gem activation from that attacker-controlled directory instead of the legitimate one, so any `require`/`gem`/`bundle` invocation during dependency installation or later deploy steps can execute attacker-supplied code (e.g., via a gem's `extconf.rb`, post-install hook, or an activated executable) on the Shipit deploy host.

Existing guards do not close this gap: `verify_signature`/`GitHubApp#verify_webhook_signature` only validate that the webhook body originated from GitHub (an internet attacker cannot forge it, but a legitimate PR label change from an unprivileged attacker's own repo is a valid, correctly-signed webhook); the `ExplicitParameters` schema only requires `labels[].name` be a `String` with no content restriction; and `EnvironmentVariables#permit`/allowlisting is never applied to the `Stack#env`/`ReviewStack#env` label-derived hash.

### Impact Explanation
An unprivileged fork PR author can achieve arbitrary command/code execution on the Shipit deploy host during the review-stack's dependency-installation or deploy/task steps by (a) opening/labeling a PR to inject an attacker-chosen environment KEY (fixed value `"true"`), and (b) committing an attacker-controlled directory/file tree in their own fork matching that value to redirect Ruby/RubyGems/Bundler resolution. This is scoped to the repository/stack for which the attacker has PR rights (their own fork against the target repo with review stacks enabled), but that is sufficient for RCE on the shared Shipit deploy host, which can affect other tenants' secrets and processes running on the same host (`GITHUB_TOKEN`, other stacks' credentials, etc.), matching the Critical - RCE via `Command`/`PTY.spawn` category.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled (`review_stacks_enabled` with `allow_all`, or `allow_with_label`/`prevent_with_label` — all satisfiable by the attacker via their own PR/label), and the dependency step must invoke `ruby`/`bundle` (default for any repo with a `Gemfile`, auto-discovered by `BundlerDiscovery#discover_bundler`). Attacker cost is minimal: open a PR from a fork and add a label; no Shipit credentials, GitHub App keys, or team membership are required. The chain is fully repeatable per repository with review stacks enabled and requires no live GitHub secrets to demonstrate the code-level divergence (the env-key injection itself, independent of the full RCE chain, is trivially and deterministically reproducible in a minitest).

### Recommendation
Apply an explicit allowlist to `Stack#env`/`ReviewStack#env` label-derived keys (e.g., restrict to a repository-configured allowlist of permitted label-flag names, or prefix them, e.g. `LABEL_<NAME>`, so they can never collide with process/loader environment variables), and additionally have `Command#unbundled_env` reject/strip any keys not present in `deploy_spec.machine_env` plus declared `VariableDefinition` names before merging onto `BASE_ENV`, consistent with how `EnvironmentVariables#permit` is already used for deploy/task `env` params.

### Proof of Concept
minitest plan (`test/lib/shipit/task_commands_test.rb`-style):
```ruby
test "#env from a review stack with a GEM_HOME label reaches Command#unbundled_env" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["gem_home"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env
  assert_equal "true", env["GEM_HOME"]  # Left side of the broken binding

  command = Shipit::Command.new("bundle install", env:, chdir: ".")
  assert_equal "true", command.unbundled_env["GEM_HOME"]  # Reaches PTY.spawn env
  # Right side of the invariant (declared allowlist) does NOT include GEM_HOME:
  refute_includes stack.cached_deploy_spec.machine_env.keys + task.definition.variables.map(&:name), "GEM_HOME"
end
```
This demonstrates that an attacker-controlled label name reaches the exact hash passed to `PTY.spawn`, violating the stated invariant that spawned-process env keys are restricted to `machine_env` and declared `VariableDefinition` names.

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

**File:** test/models/shipit/review_stack_test.rb (L59-65)
```ruby
    test "#env includes the stack's pull request labels" do
      stack = shipit_stacks(:review_stack)
      stack.pull_request.labels = ["wip", "bug"]

      assert_equal stack.env["WIP"], "true"
      assert_equal stack.env["BUG"], "true"
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

**File:** lib/shipit/task_commands.rb (L92-98)
```ruby
    def steps_directory
      if sub_directory = deploy_spec.directory.presence
        File.join(@task.working_directory, sub_directory)
      else
        @task.working_directory
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
