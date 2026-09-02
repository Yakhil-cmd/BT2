### Title
Attacker-controlled PR label `GIT_SSH_COMMAND` is merged unfiltered into `ReviewStack#env` and reaches `git` via `PTY.spawn`, hijacking the ssh transport - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` uppercases every pull-request label and sets its value to the literal string `"true"` with no whitelist, and this hash is merged into both `TaskCommands#env` and `StackCommands#env`, which are used unmodified as the `env:` for every `git` `Command` (`clone`, `fetch`, `checkout`). Because git honors `GIT_SSH_COMMAND` from the process environment to override its ssh transport, an attacker who can label their own PR `GIT_SSH_COMMAND` injects that key into the environment handed to `PTY.spawn`, replacing the ssh command used for that stack's git operations.

### Finding Description
The broken binding: the codebase's own security control on task/deploy environment variables is `command.env.keys ⊆ whitelist(variables)`, enforced via `EnvironmentVariables#permit` in `TaskDefinition#filter_envs` [1](#0-0)  and `DeploySpec#filter_deploy_envs`/`filter_rollback_envs` [2](#0-1) . `ReviewStack#env`, however, is not routed through any such whitelist: it merges every PR label, upcased, with value `"true"`, straight into the stack's env hash [3](#0-2) .

Labels are attacker-controlled and reach this method via the webhook path: `LabelCapturingHandler#capture_labels` writes `params.pull_request.labels.map(&:name)` (raw GitHub label names from the webhook payload) onto `pull_request.labels` for any active, non-archived review stack, with no signature check bypassed and no additional sanitization of label content [4](#0-3) . An attacker who owns the PR (opens it, or any collaborator who can apply labels on their own fork/PR) can name a label `GIT_SSH_COMMAND` (case-insensitive, since it's upcased).

Downstream, `TaskCommands#env` merges `@stack.env` directly with no filtering before merging fixed keys and `deploy_spec.machine_env` [5](#0-4) , and `StackCommands#env` likewise merges `@stack.env` unfiltered [6](#0-5) . `StackCommands#fetch`/`#fetch_commit`/`git_clone` and `TaskCommands#clone`/`#checkout` all pass this `env` (via the `env:` shorthand) into `Commands#git`, which constructs a `Command` [7](#0-6) . `Command#unbundled_env` merges `@env.stringify_keys` on top of `BASE_ENV` with no key restriction [8](#0-7) , and that hash is passed directly to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [9](#0-8) . `GIT_SSH_COMMAND` is a real git environment variable that git uses as the ssh transport command; setting it to `true` makes git invoke `/usr/bin/true` (or whatever `true` resolves to) instead of `ssh`, replacing the ssh transport for that stack's `git fetch`/`git clone` operations for as long as the label remains applied. Existing guards (`EnvironmentVariables#permit`, `TaskDefinition#filter_envs`, `filter_deploy_envs`) are never invoked on `Stack#env`/`ReviewStack#env`, so they do not intervene on this path.

### Impact Explanation
For any repository with review stacks enabled, an unprivileged PR author can silence or hijack the ssh transport used by that PR's review stack for `git fetch`/`git clone`, breaking or subverting the network operation of that specific stack's deploy pipeline (transport hijack). While `GIT_SSH_COMMAND=true` itself only demonstrates transport replacement (turns ssh into a no-op), the same unfiltered injection point allows the label value to be an arbitrary environment variable name mapped to `"true"`, and more importantly, since the value is always `"true"`, the more critical escalation is that other reachable env-var names honored by git or the executed steps (e.g., `GIT_SSH_COMMAND`, `GIT_PROXY_COMMAND`-style vectors) can be flipped on/off, affecting exactly the attacker's own review stack's git process. This is scoped to the review stack tied to that PR/repository; it does not cross tenant boundaries into other repositories' stacks. Matches "Critical - RCE on the deploy host via `Command`/`PTY.spawn`" only if a value more dangerous than `"true"` could be injected; as specified (`labels[label_name.upcase] = "true"`) the injected value is fixed to the string `"true"`, limiting the exploit to boolean-style environment toggles rather than arbitrary command injection into `GIT_SSH_COMMAND`'s content itself.

### Likelihood Explanation
Preconditions: `review_stacks_enabled` on the target repository, an open non-archived review stack, and the attacker's ability to label their own PR (native GitHub permission for PR authors on their own repos, or maintainers who allow external labeling). Attacker cost is zero secrets and one GitHub label action. This is fully repeatable against any repository the attacker can open PRs against with review stacks enabled.

### Recommendation
Whitelist or sanitize label-derived environment variables in `ReviewStack#env` — e.g., reject or drop label names that collide with reserved/dangerous env var names (`GIT_*`, `PATH`, `LD_PRELOAD`, etc.), or route the label hash through `EnvironmentVariables#permit` against an explicit allowed-label-variable list before merging.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb
test "#env does not allow labels to override GIT_SSH_COMMAND" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["GIT_SSH_COMMAND"]

  assert_nil stack.env["GIT_SSH_COMMAND"], "label should not inject GIT_SSH_COMMAND into stack env"
end

# test/lib/shipit/task_commands_test.rb
test "#env propagates label-derived GIT_SSH_COMMAND into TaskCommands env (current behavior)" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["GIT_SSH_COMMAND"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env
  assert_equal "true", env["GIT_SSH_COMMAND"]
end

# test/unit/deploy_commands_test.rb-style
test "StackCommands#git command inherits label-derived GIT_SSH_COMMAND unmodified" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["GIT_SSH_COMMAND"]
  commands = Shipit::StackCommands.new(stack)

  command = commands.fetch
  assert_equal "true", command.env["GIT_SSH_COMMAND"]
  assert_equal "true", command.unbundled_env["GIT_SSH_COMMAND"]
end
```

### Citations

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
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

**File:** lib/shipit/stack_commands.rb (L13-15)
```ruby
    def env
      super.merge(@stack.env)
    end
```

**File:** lib/shipit/commands.rb (L28-33)
```ruby
    def git(*args)
      kwargs = args.extract_options!
      kwargs[:env] ||= base_env
      Command.new("git", *args, **kwargs)
    end
    ruby2_keywords :git if respond_to?(:ruby2_keywords, true)
```

**File:** lib/shipit/command.rb (L91-98)
```ruby
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
