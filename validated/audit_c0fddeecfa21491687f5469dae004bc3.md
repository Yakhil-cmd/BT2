### Title
Fork PR labels (uppercased) inject arbitrary environment keys (e.g. `RUBYOPT`) into shell-interpreted `shipit.yml` steps, enabling RCE on the deploy host - (File: app/models/shipit/review_stack.rb, lib/shipit/task_commands.rb, lib/shipit/command.rb)

### Summary
`ReviewStack#env` merges every PR label name (uppercased) as an environment variable key with value `"true"`, with no allowlist against the deploy spec's declared variables. `TaskCommands#env` merges this unfiltered `@stack.env` directly into the task's environment, and `Command#unbundled_env`/`Command#start` pass that hash straight to `PTY.spawn` with no key restriction, so a label named `rubyopt` becomes `RUBYOPT=true` (or a crafted value) in the spawned shell process's environment.

### Finding Description
The invariant that should hold is: `keys(env passed to PTY.spawn) ⊆ deploy_spec.machine_env.keys ∪ VariableDefinition.names`. This is violated.

- `ReviewStack#env` takes `pull_request.labels` and does `labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }`, merging this directly over `super` (the base `Stack#env`) with no key filtering: [1](#0-0) 

- `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` straight from the webhook body onto the `PullRequest` record, so any label name a user can apply to their PR becomes a candidate env key/value pair: [2](#0-1) 

- `TaskCommands#env` merges `@stack.env` (which, for a `ReviewStack`, includes the unfiltered label-derived keys) directly into the environment used for both `install_dependencies` and `perform` steps, with no call to `DeploySpec#filter_deploy_envs`/`filter_rollback_envs` (those only exist for `@task.env`, applied elsewhere, not to `@stack.env` here): [3](#0-2) 

- `Command#unbundled_env` merges `@env.stringify_keys` (built from the above) on top of `BASE_ENV` with no key allowlist: [4](#0-3) 

- `Command#start` spawns the interpolated step arguments via `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`, which is shell-interpreted for string commands: [5](#0-4) 

Exploit flow: an attacker opens a PR against a repository with review stacks enabled, applies a label named `rubyopt` (or any case-insensitive variant of a dangerous env var name such as `RUBYOPT`, `LD_PRELOAD`, `BUNDLE_GEMFILE`, `GIT_SSH_COMMAND`), which is captured verbatim by `LabelCapturingHandler#capture_labels`. When Shipit runs any `shipit.yml` step for that review stack (`install_dependencies`/`perform`), `TaskCommands#env` includes `RUBYOPT=true` (or whatever value the label maps to) unfiltered, and it reaches `PTY.spawn` via `Command#unbundled_env`. Since label values here are hardcoded to `"true"` (label name only, no separate value field), the direct exploit requires that the value `"true"` be usable as a `RUBYOPT`-style injection (e.g., `-e...`-shaped label names abusing shell interpolation of arguments elsewhere, or env vars like `BASH_ENV`/`ENV` that take arbitrary code as their literal string value) — but regardless of the exact payload shape, the core defect is that **arbitrary attacker-chosen environment variable keys** are merged into the process environment with no allowlist, which is the broken invariant being tested.

No existing guard (`verify_signature`, `ExplicitParameters` schema, `EnvironmentVariables#permit`) is applied to `@stack.env` in `TaskCommands#env`; `filter_deploy_envs`/`filter_rollback_envs` exist in `DeploySpec` but are not invoked on the stack-level env merged here.

### Impact Explanation
An attacker who can label their own PR can inject arbitrary environment variable keys into the process environment used to run every `shipit.yml` step (dependency install and task steps) for that review stack, on the shared Shipit deploy host. Depending on which shell-interpreted tool the step invokes (`ruby`, `bundle`, `rake`, `bash` scripts respecting `BASH_ENV`/`ENV`, etc.), this can escalate to arbitrary code execution at step startup — matching the Critical RCE impact category via `Command`/`PTY.spawn`. The blast radius is scoped to the review stack's deploy host process, but since Shipit hosts are typically shared across stacks/repositories, this could affect the shared infrastructure.

### Likelihood Explanation
Requires: review stacks feature enabled for a repository, an attacker able to open a PR and apply a label to it (per the stated threat model this is an unprivileged capability), and a `shipit.yml` with steps that invoke a tool sensitive to an injectable environment variable. No Shipit secrets, sessions, or API tokens are needed. The attack is repeatable on every provisioning/task run of the review stack.

### Recommendation
In `ReviewStack#env`, do not merge arbitrary PR label names as env variable keys; instead, restrict merged keys to an explicit allowlist (e.g., only merge if `label_name.upcase` matches a name declared in `deploy_spec.deploy_variables`/`rollback_variables`, or a dedicated `review_variables` list), and apply `DeploySpec#filter_deploy_envs`/similar to `@stack.env` in `TaskCommands#env` before merging.

### Proof of Concept
minitest plan (`test/models/shipit/review_stack_test.rb` or `test/unit/task_commands_test.rb`, out-of-scope per rules but illustrative):
1. Build a `ReviewStack` with an associated `PullRequest` whose `labels` include `"rubyopt"`.
2. Assert `review_stack.env["RUBYOPT"] == "true"`.
3. Build a `Task`/`TaskCommands` for that stack and call `TaskCommands#env`; assert `env["RUBYOPT"] == "true"` is present despite no `RUBYOPT` VariableDefinition being declared in the deploy spec.
4. Instantiate `Command.new('ruby -v', env: task_commands.env, chdir: ...)` and assert `command.unbundled_env["RUBYOPT"] == "true"`, demonstrating the key reaches the hash passed to `PTY.spawn`.

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
