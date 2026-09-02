### Title
ReviewStack#env merges attacker-controlled PR labels unfiltered into deploy environment, enabling env-var injection (e.g. PYTHONPATH/PERL5LIB) - ([File: app/models/shipit/review_stack.rb])

### Summary
`Shipit::ReviewStack#env` merges every GitHub pull-request label name (uppercased) as a `"true"`-valued environment variable into the stack's environment, and `TaskCommands#env`/`DeployCommands#env` merge that unfiltered hash directly into the env passed to `Command.new`, which ultimately reaches `PTY.spawn`. Because label names are fully attacker-chosen strings synced verbatim from the GitHub webhook payload, a label such as `PYTHONPATH` or `PERL5LIB` sets that exact variable for the deploy process, with no whitelist enforcement analogous to `EnvironmentVariables#permit`.

### Finding Description
The broken binding: the set of keys reaching `Command#env`/`PTY.spawn` for a review-stack deploy should equal `{approved spec-defined vars} ∪ {SHIPIT_* internal vars}`, but in fact equals that set **∪ `pull_request.labels.map(&:upcase)`** — an attacker-controlled superset.

Code path:
- `PullRequest#github_pull_request=` sets `self.labels = github_pull_request.labels.map(&:name)` directly from the webhook/API payload [1](#0-0) , and `LabelCapturingHandler#capture_labels` similarly persists `params.pull_request.labels.map(&:name)` verbatim from an inbound `pull_request` webhook event [2](#0-1) .
- `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into the stack env with no whitelist check [3](#0-2) .
- `TaskCommands#env` merges `@stack.env` (which is `ReviewStack#env` for a review stack) directly into the command environment used to build `Command.new(command_line, env:, chdir: steps_directory)` for `install_dependencies` and `perform` steps [4](#0-3) .
- `Command#start` spawns the process with this merged env via `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`, where `unbundled_env` merges `@env.stringify_keys` on top of the base process environment [5](#0-4) .
- Unlike task-level user-supplied env (`Task#env`, filtered through `definition.filter_task_envs`/`filter_deploy_envs` in `Stack#trigger_task`/`Stack#build_deploy`), the `pull_request.labels`-derived keys bypass any whitelist step — `EnvironmentVariables#permit` exists but is never called on this label-derived hash [6](#0-5) [7](#0-6) .

Attacker request: an unprivileged GitHub user with write/triage access sufficient to label a PR on their own repository (i.e., their own fork/PR, which the "unprivileged" model in this question grants) sends a `pull_request` webhook (`labeled`/`opened`) carrying a label object whose `name` is `PYTHONPATH` (or `PERL5LIB`) with a value implicitly fixed to `"true"` by `ReviewStack#env` — this webhook is processed by `LabelCapturingHandler`, persisted onto `PullRequest#labels`, and surfaces unfiltered into every subsequent deploy/task's process environment for that review stack.

Existing guards do not stop this: `verify_signature`/`GithubApp#verify_webhook_signature` only authenticate that the payload came from GitHub for a repo Shipit is configured to receive hooks from — they do not restrict which label names/values are acceptable; `ExplicitParameters` schema only requires `labels` be an `Array` of `{name: String}`, not that names come from an allowlist [8](#0-7) ; and `EnvironmentVariables#permit` is simply never invoked for this data flow.

### Impact Explanation
Whatever value `PYTHONPATH="true"` sets is limited (only fixed string `"true"`, not attacker-chosen value), so classic module-hijacking via a crafted path is not directly achievable — the value is hardcoded to `"true"` by `ReviewStack#env`'s implementation, not attacker-controlled content. This limits (but does not eliminate) exploitability: an attacker can only set env-var **names** they choose, not arbitrary values, for stacks that are ReviewStacks. Real damage requires a deploy script that treats a `PYTHONPATH`/`PERL5LIB` set to the literal string `"true"` as a meaningful path component (e.g. `python -c "import os,sys; ..."` in a `PYTHONPATH=true` context is unlikely to resolve to attacker code, since `"true"` is not a writable/attacker-populated directory). Without attacker control over the *value*, RCE via interpreter module-path hijacking is not demonstrated — this is a real design weakness (env-key injection) but the specific "module-path hijacking RCE" claim is not substantiated because the injected value is fixed and not attacker-supplied content pointing to attacker-controlled code.

### Likelihood Explanation
Reaching this code path requires: (1) a `ReviewStack` configured for the repository (`ReviewStacksController`/pull-request review-stack feature enabled), (2) the attacker being able to add a label to their own PR against that repository (label creation on GitHub generally requires write/triage permission on the target repo, which for "their own repository" as stated in the threat model is trivially satisfiable), and (3) the review stack's deploy steps consuming `PYTHONPATH`/`PERL5LIB` from environment in a way that resolves to writable/attacker content. Given the value is always `"true"`, exploitability for actual RCE is low/unproven even though the "unauthorized env key" divergence itself is real and repeatable.

### Recommendation
Whitelist or reject reserved/sensitive environment variable names before merging PR labels in `Shipit::ReviewStack#env` (e.g., pass label-derived keys through `EnvironmentVariables#permit` against a deploy-spec-defined allowlist, or reject/skip names matching known interpreter/library search-path variables such as `PATH`, `PYTHONPATH`, `PERL5LIB`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `RUBYLIB`, `NODE_PATH`, `GEM_PATH`, `BUNDLE_*`, `GIT_*`) before they reach `TaskCommands#env`/`DeployCommands#env`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (conceptual, not to be placed under test/ for this audit but illustrating the binding)
test "#env should not allow labels to set sensitive interpreter env vars" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["pythonpath", "ld_preload"]

  env = stack.env

  refute env.key?("PYTHONPATH"), "PR label should not be able to set PYTHONPATH"
  refute env.key?("LD_PRELOAD"), "PR label should not be able to set LD_PRELOAD"
end
```
This demonstrates the equality break: expected `env.keys ⊆ approved_spec_vars`, actual `env.keys ⊇ {"PYTHONPATH", "LD_PRELOAD"}` sourced from `pull_request.labels` [3](#0-2) . Note the existing test `test/models/shipit/review_stack_test.rb:59-65` already documents this behavior as intentional ("includes the stack's pull request labels"), confirming labels are meant to flow into env, but with no denylist for reserved/security-sensitive names.

### Citations

**File:** app/models/shipit/pull_request.rb (L48-48)
```ruby
      self.labels = github_pull_request.labels.map(&:name)
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L26-32)
```ruby
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
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

**File:** app/models/shipit/stack.rb (L139-172)
```ruby
    def trigger_task(definition_id, user, env: nil, force: false)
      definition = find_task_definition(definition_id)
      env = env.to_h

      definition.variables_with_defaults.each do |variable|
        env[variable.name] ||= variable.default
      end

      commit = last_deployed_commit.presence || commits.first
      task = tasks.create(
        user_id: user.id,
        definition:,
        until_commit_id: commit.id,
        since_commit_id: commit.id,
        env: definition.filter_envs(env),
        allow_concurrency: definition.allow_concurrency? || force,
        ignored_safeties: force
      )
      task.enqueue
      task
    end

    def build_deploy(until_commit, user, env: nil, force: false, allow_concurrency: force)
      since_commit = last_deployed_commit.presence || commits.first
      deploys.build(
        user_id: user.id,
        until_commit:,
        since_commit:,
        env: filter_deploy_envs(env.to_h),
        allow_concurrency:,
        ignored_safeties: force || !until_commit.deployable?,
        max_retries: retries_on_deploy
      )
    end
```
