### Title
Unprivileged fork PR label injects `GEM_HOME` into `dependencies.override` `Command#start` env, poisoning gem resolution on the deploy host - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) into the stack's environment hash with no key allowlist, and that hash flows unfiltered into `TaskCommands#env` → `Command.new(..., env:)` → `Command#unbundled_env`, which merges the caller-supplied env **last**, letting a PR label override any base environment variable, including `GEM_HOME`, for the `dependencies.override` step's spawned process.

### Finding Description
The broken binding: the invariant should be `Command#unbundled_env.keys - BASE_ENV_ALLOWED_KEYS == ∅` for keys reaching the `dependencies.override` step, i.e. `env['GEM_HOME'] == Shipit-defined value` regardless of PR content. Instead, `env['GEM_HOME'] == pull_request.labels.map(&:upcase).include?('GEM_HOME') ? 'true' : Shipit-defined value`.

Path:
1. `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim from the webhook body onto `stack.pull_request.labels`, with no name restriction (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102`). [1](#0-0) 
2. `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into `super` (the base `Stack#env`) with no key allowlist. [2](#0-1) 
3. `TaskCommands#env` merges `@stack.env` (i.e. the `ReviewStack#env` above) into the environment used for every step, including `install_dependencies` (`dependencies.override`). [3](#0-2) 
4. `Command#initialize` stores this hash as `@env`, and `Command#unbundled_env` computes `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` — the attacker-controlled `@env` is merged **last**, so it can override any `BASE_ENV` key including `GEM_HOME`. [4](#0-3) 
5. `Command#start` passes this merged hash directly to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`, where `@chdir` is the working directory containing the checked-out fork PR branch (fully attacker-controlled content). [5](#0-4) 

Attacker's exact action: open a PR from a fork against a repo with `provisioning_behavior=prevent_with_label` and `review_stacks_enabled`, add a label named `gem_home` (case-insensitive) to their own PR, and commit a directory literally named `true` at the repository root of their branch head containing a malicious `rubygems_plugin.rb` (or poisoned gem specs). When Shipit's review stack runs its `dependencies.override` step (e.g. `bundle install`/`gem` invocation), the process is spawned with `GEM_HOME=true`, `chdir` pointing at the attacker's checked-out branch, so RubyGems/Bundler resolves the relative `GEM_HOME` against the attacker's own directory and autoloads the planted plugin/gem code, achieving code execution on the deploy host under the Shipit worker's privileges.

Existing guards do not block this: `EnvironmentVariables#permit` is only used to sanitize `deploy.variables` submitted through the UI/API (not applied to PR-label-derived env), `LabelCapturingHandler`'s `params` schema only validates types/presence of `name` (any string is accepted, confirmed by the existing test allowing emoji label names), and no code path filters or allowlists the uppercased label keys before they reach `Command#unbundled_env`. This is corroborated by the existing test `DeployCommandsTest#"#env includes the stack's pull request labels"` and `ReviewStackTest#"#env includes the stack's pull request labels"`, which already demonstrate that arbitrary uppercased label names land directly in the command's environment. [6](#0-5) [7](#0-6) 

### Impact Explanation
An unprivileged fork-PR author can force the Shipit deploy host to execute arbitrary code during the `dependencies.override` phase of their own review stack's deploy/task run, by redirecting `GEM_HOME` to a directory they populate inside their own PR branch. This is repeatable on every deploy/task run of that review stack and matches the Critical class: "RCE on the deploy host via `Command`/`PTY.spawn`." The blast radius is scoped to the repository/stack whose review stack the attacker controls, but since the deploy host and worker process are typically shared across stacks/tenants, successful code execution compromises the whole Shipit deploy host, not just that repository's sandbox.

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled` with `provisioning_behavior=prevent_with_label` (or `allow_all`/`allow_with_label`, any behavior that provisions a review stack for the PR), and the `dependencies.override`/discovered dependency step must actually invoke gem/bundler tooling that honors `GEM_HOME`. Per the audit's threat model, the attacker is assumed capable of opening a PR and labeling it themselves at no cost, and needs only to commit a directory named `true` with a plugin payload — cheap and fully repeatable across runs of the same or new PRs.

### Recommendation
Restrict the keys derived from pull-request labels in `ReviewStack#env` to a safe, allowlisted prefix (e.g. only add labels as `SHIPIT_LABEL_<NAME>` or via a dedicated non-overridable namespace) rather than merging raw uppercased label names directly as environment variable names. Additionally, in `Command#unbundled_env`, protect a set of security-sensitive keys (`GEM_HOME`, `BUNDLE_GEMFILE`, `RUBYOPT`, `LD_PRELOAD`, etc.) from being overridden by caller-supplied `@env`, or merge `@env` before `BASE_ENV`'s security-critical keys rather than after.

### Proof of Concept
minitest plan (`test/models/shipit/review_stack_test.rb` or `test/lib/shipit/deploy_commands_test.rb` style):
```ruby
test "#env allows a PR label to inject GEM_HOME into the dependencies.override step" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["gem_home"]

  env = Shipit::DeployCommands.new(stack.trigger_continuous_delivery).env
  assert_equal "true", env["GEM_HOME"]

  command = Shipit::Command.new("bundle install", env:, chdir: ".")
  assert_equal "true", command.unbundled_env["GEM_HOME"]
end
```
Binding checked on both sides: expected `command.unbundled_env["GEM_HOME"]` to be Shipit-defined/absent; actual value is the label-derived `"true"`, proving the fork-controllable label overrides the security-relevant environment key reaching `PTY.spawn`.

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
