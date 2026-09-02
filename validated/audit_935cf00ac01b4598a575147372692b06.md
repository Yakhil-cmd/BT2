### Title
Attacker-controlled PR labels can set arbitrary environment variables (including `IFS`, `PATH`, `BASH_ENV`) for deploy step scripts - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` unconditionally converts every GitHub PR label into an environment variable (`LABEL_NAME.upcase => "true"`) with no allowlist, and this hash flows unfiltered through `TaskCommands#env` into `Command#unbundled_env`, which is merged last (after `PATH`) before `PTY.spawn`. Any PR label whose upcased form matches a shell-meaningful or security-sensitive variable name (`IFS`, `PATH`, `BASH_ENV`, `ENV`, `LD_PRELOAD`, etc.) silently overrides that variable for every deploy/rollback/task step run against that review stack.

### Finding Description
Binding the code should guarantee: `env["IFS"]` (or any reserved variable) used by step scripts during task execution == Shipit's intended default (unset/whitespace), independent of PR label content.

What actually happens:
- `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |l, h| h[l.upcase] = "true" }` into the stack env with no filtering: [1](#0-0) 
- `TaskCommands#env` merges `@stack.env` (which includes the label-derived hash) directly into the command environment, with no whitelist applied: [2](#0-1) 
- `Command#unbundled_env` merges `@env.stringify_keys` **last**, after `BASE_ENV` and after the explicit `PATH` assignment, so any key in the label-derived hash (including `PATH`, `IFS`, `BASH_ENV`) wins: [3](#0-2) 
- `Command#start` passes this merged hash straight into `PTY.spawn`: [4](#0-3) 

By contrast, when Shipit does want to whitelist user-influenced env vars (e.g. deploy/task-triggered custom env), it routes them through `EnvironmentVariables#permit`, which raises `NotPermitted` for any key not in the task/deploy definition's variable list: [5](#0-4) . This guard is never applied to the label-derived env produced by `ReviewStack#env` — confirmed by the existing test `DeployCommandsTest#env includes the stack's pull request labels`, which shows arbitrary uppercased label names appear directly in the command env unfiltered: [6](#0-5) .

Exploit flow: a GitHub `pull_request` `labeled` webhook (`action: "labeled"`, label `name: "ifs"`) is captured by `LabelCapturingHandler#capture_labels`, which persists `pull_request.labels` verbatim from the payload: [7](#0-6) . On the next deploy/task run for that review stack, `TaskCommands#env` produces `env["IFS"] = "true"`, and `PTY.spawn` launches the shell step with that value, corrupting word-splitting for any step script that relies on default `IFS` (e.g. `for f in $list`).

None of the listed guards (`verify_signature`, `ExplicitParameters`, `require_permission!`, model validations) address this, because they authenticate/validate the webhook shape and stack ownership, not the semantic content of label strings once they are turned into environment variables.

### Impact Explanation
A PR label becomes an unsanitized environment variable injected into every subsequent step-script invocation for that review stack's tasks/deploys. Colliding with `IFS` corrupts word-splitting in any `/bin/sh`-based step relying on default `IFS`, which can change which tokens/commands a script executes — an unintended command execution path on the deploy host. The same unfiltered-merge mechanism also allows collision with `PATH`, `BASH_ENV`, `ENV`, or `LD_PRELOAD` (the merge order in `unbundled_env` puts `@env` after the explicit `PATH` assignment), which is a stronger primitive than pure `IFS` corruption and can lead to full command substitution/RCE if any step script sources `BASH_ENV` or resolves binaries via `PATH`. This is scoped to whatever repository/stack the attacker can label PRs on, and repeats on every task/deploy run against that stack while the label is applied.

### Likelihood Explanation
Preconditions: review stacks must be enabled for the repository, and at least one deploy step must be a shell script relying on default `IFS`/`PATH`. Per the stated attacker model, the attacker only needs to be able to add a label to a PR on a repository being tracked by Shipit's review-stack feature — no Shipit credentials, session, or GitHub App secrets are required, and the webhook payload only needs valid GitHub webhook signature (produced by GitHub itself, not the attacker) for a real label event. Cost is a single GitHub UI action (adding a label named `ifs`), fully repeatable and requires no code changes to `shipit.yml` beyond an ordinary shell step.

### Recommendation
Do not allow PR-label-derived environment variables to collide with reserved/shell-significant names. Either: (1) restrict label-derived variables to a prefixed namespace (e.g. `LABEL_<NAME>`) instead of the raw uppercased label, or (2) apply a denylist/allowlist (similar to `EnvironmentVariables#permit`) in `ReviewStack#env` that rejects/strips names like `IFS`, `PATH`, `BASH_ENV`, `ENV`, `LD_PRELOAD`, `SHELL`, etc. before merging, and (3) ensure `Command#unbundled_env` cannot let arbitrary merged env override `PATH` (compute `PATH` after merging `@env`, or explicitly protect it).

### Proof of Concept
Add to `test/lib/shipit/task_commands_test.rb` (or a new Command integration test):
```ruby
test "#env allows a PR label to override IFS for step execution" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["ifs"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env

  assert_equal "true", env["IFS"] # attacker-controlled, should not equal Shipit's intended default (unset)
end

test "Command#start executes with attacker-controlled IFS from a PR label" do
  Dir.mktmpdir do |dir|
    command = Shipit::Command.new(
      ["sh", "-c", 'echo "IFS=[$IFS]"'],
      chdir: dir,
      env: { "IFS" => "true" } # simulates ReviewStack#env merging the "ifs" label
    )
    output = command.run!
    assert_includes output, "IFS=[true]" # confirms the shell's IFS == attacker value, not Shipit's default
  end
end
```
Both assertions demonstrate the equality `env["IFS"] == attacker_label_value` rather than the intended `env["IFS"] == Shipit_default`, confirming the binding is broken.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```
