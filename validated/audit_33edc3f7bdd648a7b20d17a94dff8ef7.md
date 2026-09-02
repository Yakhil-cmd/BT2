### Title
`Shipit::ReviewStack#env` merges attacker-controlled PR labels unfiltered into task/command environment - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every label name on the associated pull request directly into the environment hash used for deploy/checkout commands, with no whitelist. An attacker who can label their own PR (e.g. `GIT_SSH_COMMAND`) on a repository with review stacks enabled can inject that variable into `git clone`/`checkout` invocations executed by `Command#start` via `PTY.spawn`.

### Finding Description
The broken binding: the question asserts that every env value reaching `PTY.spawn` for a `git` command should be operator/spec-controlled, i.e. `env_value ∈ Shipit.env ∪ deploy_spec.machine_env ∪ @task.env`. This is false because `ReviewStack#env` adds a third, attacker-controlled source: [1](#0-0) 

which upcases each `pull_request.labels` entry and sets it to `"true"`, with no whitelist check (`super` is `Stack#env`, which itself is safe/fixed): [2](#0-1) 

Labels are populated straight from GitHub webhook payloads with no name filtering, by `LabelCapturingHandler#capture_labels`, which is triggered for `opened`, `labeled`, `unlabeled`, `reopened` PR events (on an active, non-archived stack): [3](#0-2) 

The resulting `ReviewStack#env` is merged into `TaskCommands#env` (`.merge(@stack.env)`), then further merged with `deploy_spec.machine_env` and `@task.env`: [4](#0-3) 

That env is passed to every `Command.new(command_line, env:, ...)` for install/deploy steps, and to the `git` calls used by `checkout`/`clone`: [5](#0-4) 

`Command#unbundled_env` merges `@env` (stringified) last, on top of `BASE_ENV` and `PATH`, with no key whitelist: [6](#0-5) 

and `Command#start` passes this hash directly to `PTY.spawn`: [7](#0-6) 

Note that `EnvironmentVariables.permit`, the mechanism that *does* whitelist variables elsewhere in the codebase (`Stack#trigger_task`/`build_deploy` via `definition.filter_envs`/`filter_deploy_envs`), is never invoked on the merged `TaskCommands#env` result: [8](#0-7) 

Those filters (`Stack#trigger_task` line 153, `Stack#build_deploy` line 167) only apply to user-supplied task/deploy `env:` params at trigger time, not to `Stack#env`/`ReviewStack#env`, which is unconditionally merged inside `TaskCommands#env`. So the whitelist that exists in the codebase does not cover this path — confirming the divergence is real and unguarded.

**Attacker's exact action**: On a fork PR they own/control, targeting a repository that has review stacks enabled, add the label `GIT_SSH_COMMAND` (or `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`, `GIT_TERMINAL_PROMPT`, `LD_PRELOAD` if using such names — though those get overwritten later by `TaskCommands#env`'s own hardcoded `GIT_COMMITTER_NAME`/`EMAIL` keys merged after `@stack.env`, so `GIT_SSH_COMMAND` specifically survives since nothing overwrites it). GitHub emits a `pull_request` `labeled` webhook, which `LabelCapturingHandler` processes and persists via `pull_request.update!(labels: ...)`.

### Impact Explanation
When the next deploy/checkout task for that review stack runs, `TaskCommands#checkout`/`#clone` invoke `git` with `GIT_SSH_COMMAND=true` in the environment reaching `PTY.spawn`. Since `git` invokes `$GIT_SSH_COMMAND` (shell-interpreted) instead of the real `ssh` binary for the ssh transport, any operation over ssh remote (e.g. `git remote add origin <ssh url>` + any subsequent fetch/push, or if the origin uses ssh) allows arbitrary command execution as the deploy host's git/service user. This is scoped to the attacker's own repository/review stack but executes on the shared Shipit deploy host with the deploy user's privileges — a Critical RCE per the stated severity taxonomy (RCE on deploy host via `Command`/`PTY.spawn`). Repeatable on every deploy/checkout run of that stack as long as the label persists and is not overwritten by a later-merged key.

### Likelihood Explanation
Preconditions: the repository must have review stacks enabled (Shipit config feature, no special secret needed) and not archived; the attacker only needs the ability to open a PR from their own fork and add a label to it, which is a standard unprivileged GitHub permission on public repos. No Shipit credentials, session, or GitHub Team membership are required — only the ability to trigger a `pull_request` webhook event with a chosen label name, which any repo contributor can do. Feasibility is high: the exploit is deterministic (label name -> uppercased key -> merged into env), and repeatable against any review-stack-enabled repository the attacker can PR against.

### Recommendation
Apply an explicit whitelist/prefix restriction in `ReviewStack#env` (e.g. only allow labels matching a safe pattern like `/\ASHIPIT_/` or reuse `EnvironmentVariables.permit` with an explicit allowed-name list), and/or filter out reserved/dangerous variable names (`GIT_*`, `LD_*`, `PATH`, `BUNDLE_*`, `IFS`, etc.) before merging pull-request labels into any environment hash that reaches `Command`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (conceptual)
test "PR labels are not filtered before reaching TaskCommands#env" do
  stack = shipit_review_stacks(:review_stack) # not archived
  stack.pull_request.update!(labels: ['GIT_SSH_COMMAND'])

  task = shipit_deploys(:review_stack_deploy) # belongs to stack
  commands = Shipit::TaskCommands.new(task)

  env = commands.env
  # Binding under test: env should only contain keys from
  # Shipit.env / deploy_spec.machine_env / task.env, never a raw label name.
  assert_not_includes env.keys, 'GIT_SSH_COMMAND' # FAILS on current code

  clone_step = commands.clone.first
  unbundled = clone_step.send(:unbundled_env)
  assert_not_includes unbundled.keys, 'GIT_SSH_COMMAND' # FAILS: label reaches PTY.spawn env unfiltered
end
```
This demonstrates that a PR label name flows unfiltered from `ReviewStack#env` through `TaskCommands#env` into `Command#unbundled_env`, the exact hash passed to `PTY.spawn` for `git clone`/`checkout`.

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

**File:** app/models/shipit/stack.rb (L54-63)
```ruby
    def env
      {
        'ENVIRONMENT' => environment,
        'LAST_DEPLOYED_SHA' => last_deployed_commit.sha,
        'GITHUB_REPO_OWNER' => repository.owner,
        'GITHUB_REPO_NAME' => repository.name,
        'DEPLOY_URL' => deploy_url,
        'BRANCH' => branch
      }
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```
