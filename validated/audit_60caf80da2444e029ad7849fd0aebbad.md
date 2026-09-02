### Title
Pull request label named 'PATH' hijacks the deploy host's PATH via `ReviewStack#env` → `Command#unbundled_env` - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` blindly turns every PR label into an environment variable (`label_name.upcase => "true"`) with no name filtering, and this hash is merged into `Command`'s final environment *after* `Command#unbundled_env` computes the safe `PATH`. An attacker who can label their own PR "PATH" (or "path") on a review-stack-enabled repository overrides the deploy host's `PATH` with the literal string `"true"` for every task/deploy command executed against that stack.

### Finding Description
The broken binding: the set of keys allowed into `Command#unbundled_env`'s `@env` should be constrained to `deploy_spec.machine_env` / task `VariableDefinition`-permitted keys (i.e. `EnvironmentVariables#permit`), but in practice `Command#unbundled_env`'s `@env` also contains **arbitrary attacker-controlled keys derived from GitHub PR labels**, unfiltered by `permit`.

Path:
1. `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` directly into `PullRequest#labels` with no name allow-list or reserved-word check: [1](#0-0) . The handler runs for `opened`, `labeled`, `unlabeled`, and `reopened` events on any non-archived stack: [2](#0-1) . The `params` schema only requires `labels[].name` be a `String`, no restriction on its value (test confirms even emoji is accepted): [3](#0-2) .
2. `Shipit::ReviewStack#env` converts every persisted label into an environment entry `label_name.upcase => "true"` and merges it over the base stack env: [4](#0-3) .
3. `Shipit::TaskCommands#env` merges `@stack.env` (which is `ReviewStack#env` for review stacks) into the task environment, followed only by hardcoded keys that never touch `PATH`, then `deploy_spec.machine_env` and `@task.env`: [5](#0-4) . None of these later merges go through `EnvironmentVariables#permit`; that sanitizer is only invoked from `DeploySpec#filter_deploy_envs`/`filter_rollback_envs` and `TaskDefinition#filter_envs`, used solely for user-supplied API/controller params (`deploys_controller.rb`, `rollbacks_controller.rb`), never for `stack.env`: [6](#0-5) .
4. This full hash is passed as `env:` into `Command.new(command_line, env:, chdir: ...)` in `install_dependencies`/`perform`: [7](#0-6) .
5. `Command#unbundled_env` computes the safe `PATH` first, then merges the caller-supplied `@env` **on top**, so a `'PATH'` key in `@env` wins: [8](#0-7) . `PTY.spawn` then uses this hijacked env for every git/bundle/cap invocation: [9](#0-8) .

Existing guards do not stop this: webhook signature verification only authenticates that the payload truly came from GitHub for that repository — it does not restrict what label name a PR author on that repository can attach, and the attacker model here explicitly includes "any GitHub user who can ... label their own PR" on a repository they control/own with `review_stacks_enabled`. `EnvironmentVariables#permit`/`VariableDefinition` allow-lists exist but are never applied to `stack.env`/`ReviewStack#env` output.

### Impact Explanation
Setting the PR label to `PATH` causes every subsequent task/deploy on that review stack to run with `PATH="true"`, so `PTY.spawn` resolves `git`, `bundle`, `cap`, and all deploy-step binaries by searching `.` (cwd) or failing outright, letting an attacker who also controls files in the checked-out working directory (e.g. a file literally named `git` in the repo) redirect execution to attacker-supplied code — this is RCE-adjacent command-resolution hijacking on the deploy host, scoped to the review stack for that repository. Repeatable on every PR/label update to any repository with `review_stacks_enabled`.

### Likelihood Explanation
Requires only: the target repository has `review_stacks_enabled`, and the attacker can open a PR and apply a label named `PATH` to it — both are within the stated attacker capability ("label their own PR" on a repo they can act on). No secrets, no elevated GitHub role, no Shipit session needed. Cost is a single PR + label action.

### Recommendation
Sanitize PR-label-derived environment keys in `ReviewStack#env` by rejecting/blacklisting reserved variable names (e.g. `PATH`, `BUNDLE_*`, `GIT_*`, `HOME`) before merging, or route all label-derived env vars through an `EnvironmentVariables#permit`-style allow-list, and ensure `Command#unbundled_env` never lets caller-supplied `@env` override `PATH` (e.g. compute `PATH` last, or reject a `PATH` key from `@env` explicitly).

### Proof of Concept
```ruby
# test/lib/shipit/task_commands_test.rb
test "#env cannot override PATH via a malicious pull request label" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["PATH"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env
  command = Shipit::Command.new("true", env: env, chdir: ".")

  assert_equal "true", env["PATH"] # attacker-controlled value made it into the env hash
  refute_equal Shipit::Command::BASE_ENV["PATH"], command.unbundled_env["PATH"]
  refute_match(/\/(usr|bin|bundle)/, command.unbundled_env["PATH"]) # real PATH is gone
end
```

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L26-31)
```ruby
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L51-56)
```ruby
          def capture_labels?
            opened_active_stack? ||
              labeled_active_stack? ||
              unlabeled_active_stack? ||
              reopened_active_stack?
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

**File:** lib/shipit/task_commands.rb (L17-27)
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

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
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
