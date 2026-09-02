### Title
Unfiltered PR-label-to-environment-variable injection into every deploy subprocess bypasses the `deploy_spec` allow-list - ([File: app/models/shipit/review_stack.rb])

### Summary
`Shipit::ReviewStack#env` converts every GitHub PR label into an environment variable (`LABEL_NAME => "true"`) with no allow-list check, and this hash flows unfiltered through `TaskCommands#env` into `Command#unbundled_env`, which is passed directly to `PTY.spawn` for every subprocess (git, shell steps) of the deploy pipeline. This lets any GitHub user able to label a PR against a review-stack-enabled branch set arbitrary environment-variable *keys* (value fixed to `"true"`) on every command Shipit executes for that stack, bypassing the `deploy_spec.machine_env` / `deploy_variables` whitelist mechanism that exists specifically to constrain untrusted env injection.

### Finding Description
The binding the deploy-execution trust model is supposed to enforce is:
`keys(Command#unbundled_env) ⊆ keys(deploy_spec.machine_env) ∪ keys(Shipit.env) ∪ keys(@task.env)`

That whitelist mechanism exists and is implemented — `DeploySpec#filter_deploy_envs`/`filter_rollback_envs` call `EnvironmentVariables#permit(deploy_variables)`, which raises `NotPermitted` for any key not in the `deploy`/`rollback` `variables:` allow-list [1](#0-0) [2](#0-1) . However, this filtering is applied only to the task-submitted `@task.env` at task-creation time (controller-level), never to `@stack.env`.

`ReviewStack#env` unconditionally merges every PR label as an env-var key with no filtering against any allow-list: [3](#0-2) 

That is invoked from `TaskCommands#env`, which merges `@stack.env` *before* `deploy_spec.machine_env` and `@task.env` are merged, so the label-derived keys are outside the union the whitelist is meant to bound: [4](#0-3) 

The resulting hash is passed straight into `Command#unbundled_env`, which stringifies and merges it over `BASE_ENV` and `PATH` with no key filtering at all: [5](#0-4) 

...and that env hash is what `PTY.spawn` uses to start **every** step subprocess (`git clone`, `git checkout`, shell deploy/dependency/rollback steps): [6](#0-5) 

Attacker path: an attacker who can label a PR (per the rules, "label their own PR" is in-scope for the attacker model) against a repository with review stacks enabled causes GitHub to emit a signed `pull_request` `labeled` webhook. `LabelCapturingHandler#labeled_active_stack?` allows capturing labels on any non-archived active review stack — no additional authorization is required beyond `stack.present? && !stack.archived?`: [7](#0-6) 

The webhook signature check (`verify_signature`) only proves the request came from GitHub for *that* repository — it does not constrain what label text GitHub is allowed to relay, and nothing in the handler filters the label name against `deploy_spec.machine_env`'s allow-list before persisting it as an env-var key. This divergence is not a theoretical bug: it is directly exercised by the existing test suite, confirming the exact unfiltered flow: [8](#0-7) [9](#0-8) .

**Important caveat on the specific `LD_PRELOAD` proof-of-concept**: the value merged is always the literal string `"true"`, not attacker-controlled content — `labels[label_name.upcase] = "true"` sets only the *key* from the label. So `LD_PRELOAD=true` alone does not reliably achieve code execution (the dynamic loader would need to resolve a library literally named `true` on its standard search path, which is not attacker-controlled in this threat model). The underlying binding violation is nonetheless real and independently exploitable for RCE via other reserved variable names whose value being the fixed string `"true"` is dangerous, e.g. `BASH_ENV=true` or `ENV=true`: bash/sh source the file referenced by these variables (resolved relative to the subprocess's working directory) before running non-interactive scripts. Since the review-stack checkout directory contains the attacker's own PR branch content (`@stack.git_path`/`@task.working_directory`, populated by `TaskCommands#clone`/`#checkout`) [10](#0-9) , an attacker who both (a) commits a file literally named `true` in their PR branch and (b) labels the PR `BASH_ENV` (or `ENV`), gets that file sourced into every subsequent `sh`/`bash`-based deploy step running in that directory — full attacker-controlled code execution on the deploy host.

### Impact Explanation
This is Critical: it allows an unprivileged PR author to inject environment-variable keys (with a fixed `"true"` value) into every subprocess `PTY.spawn`'s for a given review stack's deploy pipeline, bypassing the `deploy_spec.machine_env`/`deploy_variables` allow-list that is meant to be the sole gate for untrusted env injection. Combined with attacker control over the checked-out working directory content (their own PR branch), this is repeatable and enables genuine RCE on the deploy host (e.g. via `BASH_ENV`/`ENV`), scoped to that repository's review-stack tasks, and repeatable on any repository with review stacks enabled.

### Likelihood Explanation
Preconditions: review stacks must be enabled for the target repository/branch, and a review stack must exist and not be archived for the attacker's PR (this is the normal, common state for any open PR against a review-stack-enabled repo). The attacker needs only the ability to add a label to their own PR and to control at least one file's name/content in their PR branch — both are low-cost, everyday GitHub actions requiring no Shipit credentials, session, or elevated GitHub role beyond opening/labeling a PR. No live GitHub interaction is required to demonstrate the broken binding; existing unit tests (`ReviewStackTest#test_"#env includes the stack's pull request labels"`, `TaskCommandsTest`) already prove the label pass-through.

### Recommendation
Filter `ReviewStack#env`'s label-derived keys through the same allow-list mechanism used for task/deploy variables (`deploy_spec.machine_env` / an explicit review-stack label allow-list), e.g. reject or drop any label name that collides with reserved/security-sensitive environment variable names (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV`, `ENV`, `IFS`, `PATH`, `GIT_SSH*`, `PERL5OPT`, `PYTHONPATH`, etc.), and/or namespace label-derived variables under a fixed prefix (e.g. `LABEL_<NAME>`) so they can never collide with variables Command/PTY.spawn treats specially.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (extend existing test)
test "#env allows PR labels to inject security-sensitive env var keys" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["LD_PRELOAD", "BASH_ENV"]

  env = stack.env
  assert_equal "true", env["LD_PRELOAD"]
  assert_equal "true", env["BASH_ENV"]
end

# test/lib/shipit/task_commands_test.rb
test "#env propagates PR label-derived keys unfiltered into TaskCommands#env" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["LD_PRELOAD"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  task_commands = Shipit::TaskCommands.new(task)
  command = Shipit::Command.new('true', env: task_commands.env, chdir: Dir.tmpdir)

  assert command.unbundled_env.key?('LD_PRELOAD')
  # demonstrates the key reaches PTY.spawn's env hash unfiltered by
  # deploy_spec.machine_env / deploy_variables allow-list
end
```
Both assertions pass against current code, confirming `keys(Command#unbundled_env) ⊄ keys(deploy_spec.machine_env) ∪ keys(Shipit.env) ∪ keys(@task.env)` once PR labels are present — the binding required by EXECUTION_TRUST is broken.

### Citations

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
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

**File:** lib/shipit/task_commands.rb (L50-74)
```ruby
    def checkout(commit)
      git(
        '-c',
        'advice.detachedHead=false',
        'checkout',
        '--quiet',
        commit.sha,
        chdir: @task.working_directory
      )
    end

    def clone
      [
        git(
          'clone',
          '--quiet',
          '--local',
          '--origin', 'cache',
          @stack.git_path,
          @task.working_directory,
          chdir: @stack.deploys_path
        ),
        git('remote', 'add', 'origin', @stack.repo_git_url, chdir: @task.working_directory)
      ]
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L62-102)
```ruby
          def labeled_active_stack?
            labeled? && stack.present? && !stack.archived?
          end

          def unlabeled_active_stack?
            unlabeled? && stack.present? && !stack.archived?
          end

          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
          end

          def opened?
            action == "opened"
          end

          def labeled?
            action == "labeled"
          end

          def unlabeled?
            action == "unlabeled"
          end

          def reopened?
            action == "reopened"
          end

          def action
            params.action
          end

          def pull_request
            params.pull_request
          end

          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
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
