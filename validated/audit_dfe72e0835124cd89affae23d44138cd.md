### Title
Unsanitized PR label names injected into deploy environment allow overriding `PATH` (and any other env var) on the deploy host - (`app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` merges every PR label name (upcased, value `"true"`) directly into the environment used to build deploy `Command`s, with no whitelist check. Because `Command#unbundled_env` layers `@env.stringify_keys` on top of the computed `PATH`, an attacker who can label their own PR with `PATH` can corrupt `PATH` for every command run on the deploy host for that review stack.

### Finding Description
The broken binding: the set of keys reaching `PTY.spawn` via `Command#unbundled_env` is expected to equal `deploy_spec.machine_env`'s whitelisted keys, but in practice it also includes `pull_request.labels.map(&:upcase)`, which are never checked against any whitelist.

Trace:
1. Attacker opens a PR on a fork of a repository that has review stacks enabled, adds a label literally named `PATH`, then closes/reopens the PR. GitHub sends legitimately-signed `pull_request` webhooks for these real actions — no signature bypass is needed since these are genuine GitHub events for an app already installed on the target repo.
2. `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler#capture_labels` persists the raw label names verbatim: `pull_request.update!(labels: params.pull_request.labels.map(&:name))` [1](#0-0) , and it fires on `reopened_active_stack?` for an existing non-archived stack [2](#0-1) .
3. `ReviewStack#env` merges `pull_request.labels` upcased with value `"true"` over `super`, with no filtering: `labels[label_name.upcase] = "true"` [3](#0-2) .
4. `TaskCommands#env` merges `@stack.env` into the final task environment, and only afterwards merges `deploy_spec.machine_env` — but `machine_env` only adds its own whitelisted keys, it does not strip unlisted ones already present [4](#0-3) .
5. `Command#unbundled_env` computes `BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)` — the caller-supplied `@env` (which now contains `"PATH" => "true"`) wins over the computed `PATH` [5](#0-4) , and this hash is passed straight to `PTY.spawn` in `start` [6](#0-5) .

`EnvironmentVariables#permit` exists and does exactly the whitelist check that would prevent this [7](#0-6) , but it is never invoked on the merged environment before it reaches `Command.new`/`unbundled_env`; it is only used elsewhere (e.g., for interpolation and unrelated env sanitization paths). Consequently a plain PR label name overrides `PATH` for every step executed for that deploy/rollback task on the review stack.

### Impact Explanation
Once `PATH` is set to `"true"`, all subsequent `git`, `bundle`, and deploy-step commands executed via `Command`/`PTY.spawn` for that task lose the normal `$PATH` and resolve binaries relative to the current working directory only. Combined with an attacker-controlled repository (their own fork/PR content, which is checked out into the working directory for the review stack), this enables execution of an attacker-supplied "binary" placed at a path that collides with a command name invoked during the deploy steps (e.g. `git`, `bundle`), yielding remote code execution on the deploy host in the context of the Shipit worker process. This is scoped to the repository/stack owning the review stack, but any attacker who can open/label a PR against a review-stack-enabled repository can reach it — this is a Critical impact (RCE on the deploy host via `Command`/`PTY.spawn`).

### Likelihood Explanation
Requires: review stacks enabled for the target repository (`allow_all` or similar fork-PR review-stack policy) and an existing, non-archived `ReviewStack` for the PR — both explicitly stated as in-scope preconditions. The attacker needs no Shipit credentials, no GitHub App secrets, and no maintainer status — only the ability to open a PR, add a label to it, and close/reopen it, all of which are self-service actions on their own fork. This is fully repeatable and requires no timing race or privileged access, making it highly feasible wherever review stacks are enabled for external contributions.

### Recommendation
In `Shipit::ReviewStack#env`, do not merge raw, attacker-controlled label names as environment variable keys/values. At minimum, filter label-derived keys through `EnvironmentVariables#permit` against the deploy spec's whitelist (e.g. `machine_env`/`VariableDefinition` list) before merging, and/or reject label names that collide with reserved/security-sensitive variable names such as `PATH`, `BUNDLE_*`, `LD_PRELOAD`, etc. Ideally, route review-stack label variables through the same whitelist mechanism (`deploy_spec.review_variables`/`permit`) used for other task/stack env sources instead of merging unchecked.

### Proof of Concept
```ruby
test "review stack labels can override PATH in the deploy environment" do
  stack = shipit_stacks(:review_stack) # or create a ReviewStack fixture
  stack.pull_request.update!(labels: ["PATH"])

  task_commands = Shipit::TaskCommands.new(shipit_deploys(:review_stack_deploy))
  assert_equal "true", task_commands.env["PATH"]

  command = Shipit::Command.new("echo hello", env: task_commands.env, chdir: Dir.tmpdir)
  assert_equal "true", command.unbundled_env["PATH"]
end
```
This demonstrates that a PR label named `PATH` flows unfiltered from `ReviewStack#env` through `TaskCommands#env` into `Command#unbundled_env`, confirming the equality `Command#unbundled_env["PATH"] == pull_request.labels-derived value` instead of the expected whitelisted/system `PATH`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L70-72)
```ruby
          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
          end
```

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

**File:** lib/shipit/command.rb (L85-92)
```ruby
    def start(&block)
      return if @started

      @control_block = block
      @out = @pid = nil
      FileUtils.mkdir_p(@chdir)
      begin
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
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
