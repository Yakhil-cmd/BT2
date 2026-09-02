### Title
Unfiltered PR label names become process environment variables (e.g. `PROMPT_COMMAND`) for `tasks.<name>.steps` on ReviewStacks - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` merges every pull-request label name, uppercased, as an environment-variable key with no allowlist, and `LabelCapturingHandler#capture_labels` persists label names verbatim from the webhook payload with no format restriction. Because `TaskCommands#env` merges `@stack.env` unfiltered into the environment used to build `Command` instances for `tasks.<name>.steps`, an attacker who can label a fork PR (e.g. `PROMPT_COMMAND`) can inject that key into the environment that `Command#start` passes to `PTY.spawn` on the deploy host.

### Finding Description
The invariant that should hold is: `env(tasks.<name>.steps step) ∩ {attacker-chosen key names} = ∅` — only the fixed key set produced by `Stack#env`/`TaskCommands#env` (`ENVIRONMENT`, `LAST_DEPLOYED_SHA`, `GITHUB_REPO_OWNER`, `GITHUB_REPO_NAME`, `DEPLOY_URL`, `BRANCH`, `SHIPIT_USER`, `EMAIL`, etc., [1](#0-0) ) should reach `Command`. In practice this is violated:

1. `LabelCapturingHandler` accepts arbitrary label names from the webhook body with only a `String` type constraint, no format/allowlist validation, and persists them verbatim onto `pull_request.labels`: [2](#0-1) , schema at [3](#0-2) .
2. `ReviewStack#env` merges these labels, uppercased, directly as environment variable keys with value `"true"`, with no key allowlist: [4](#0-3) .
3. `TaskCommands#env` merges `@stack.env` unfiltered into the env used for both `install_dependencies` and `perform` (the `tasks.<name>.steps` command list): [5](#0-4) , and steps are built as `Command.new(command_line, env:, chdir: steps_directory)` [6](#0-5) .
4. `Command#unbundled_env` stringifies and merges `@env` directly on top of `BASE_ENV`, and `Command#start` passes the result to `PTY.spawn`: [7](#0-6) [8](#0-7) .

Note that only `@task.env` (explicit deploy/task variables) is passed through `TaskDefinition#filter_envs`/`Stack#filter_deploy_envs` at trigger time (`app/models/shipit/stack.rb` lines 139-172); `@stack.env`, which is what `ReviewStack#env` overrides, receives no such filtering anywhere in `TaskCommands#env`. There is no allowlist of permitted keys applied to the label-derived hash before it is merged into the process environment.

Exploit flow: attacker opens a fork PR against a repository configured with `provisioning_behavior: allow_with_label`, then labels the PR with a label literally named `PROMPT_COMMAND` (or any mixed case, since it is `.upcase`d). GitHub's `pull_request` `labeled` webhook is delivered to `POST /webhooks` for the base repository (which Shipit already trusts because the hook was registered there), `LabelCapturingHandler` stores the label untouched, and the next time a `tasks.<name>.steps` task or deploy runs on that ReviewStack, `PROMPT_COMMAND=true` is present in the spawned process's environment. If the step script itself invokes an interactive bash sub-shell (an "interactive-ish step" — e.g. a debug/read prompt, `bash -i`, or any tool that inherits and honors `PROMPT_COMMAND`), the attacker-named value executes as a shell command before each prompt.

None of the existing guards intercept this: `verify_signature`/webhook signature checks only prove the webhook came from GitHub for that repo, not that the label content is safe; the `ExplicitParameters` schema for `LabelCapturingHandler` only requires `name: String`; there is no `EnvironmentVariables#permit`-style filtering applied to `ReviewStack#env`'s merged hash; and `Repository`/`Stack` model validations only constrain `environment`/`branch`/`deploy_url` formats, not PR labels or the resulting env keys.

### Impact Explanation
An unprivileged fork contributor able to label their own PR can inject an attacker-chosen environment-variable name/value pair into the process environment used for `tasks.<name>.steps`/deploy steps on that repository's ReviewStack. Because `PROMPT_COMMAND` (and similarly dangerous variables like `BASH_ENV`, `ENV`, `LD_PRELOAD` for compiled tools) has no allowlist protection, in configurations where a step's script triggers an interactive-capable shell, this can result in arbitrary command execution on the Shipit deploy host under the deploy user's privileges — matching the Critical/RCE class. The blast radius is scoped to the ReviewStack of the targeted repository (one tenant per exploit), but is repeatable against any repository using `allow_with_label` review stacks and any task/deploy whose steps spawn an interactive-capable shell.

### Likelihood Explanation
Preconditions: the target repository must use ReviewStacks (fork PR-based review apps) with `provisioning_behavior: allow_with_label`, and its `shipit.yml` `tasks.<name>.steps` (or deploy steps) must include a step that ends up honoring `PROMPT_COMMAND` (e.g., invokes an interactive bash shell, `bash -i`, or a wrapper that sources shell rc-like behavior). The attacker only needs the ability to open a PR and apply a label to it — no Shipit credentials, GitHub App key, or webhook secret required. The mechanism (unfiltered label → unfiltered env merge → unfiltered `Command` env) is unconditional and 100% reproducible for any label name; the only uncertain factor is whether a given repo's step definitions are "interactive-ish" enough for `PROMPT_COMMAND` specifically to fire, which is workflow-dependent.

### Recommendation
Restrict `ReviewStack#env`'s label-derived merge to an explicit allowlist of permitted key names/patterns (e.g., only keys matching a documented `LABEL_<name>` prefix, or reject reserved/dangerous names such as `PROMPT_COMMAND`, `BASH_ENV`, `ENV`, `LD_PRELOAD`, `PATH`, `IFS`). Additionally, run all `TaskCommands#env` output (including `@stack.env`) through the same `filter_task_envs`/`filter_deploy_envs`-style safe-list mechanism already used for explicit task/deploy variables before it reaches `Command.new`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (or lib/shipit/task_commands_test.rb)
test "PR label names inject arbitrary env keys into tasks.<name>.steps command env" do
  stack = shipit_stacks(:review_stack) # or build a ReviewStack fixture with provisioning_behavior allow_with_label
  pull_request = stack.pull_request
  pull_request.update!(labels: ["prompt_command"]) # simulates LabelCapturingHandler#capture_labels persisting an attacker-chosen label verbatim

  env = stack.env
  assert_equal "true", env["PROMPT_COMMAND"], "expected fork-controllable label to become PROMPT_COMMAND env key"

  task = shipit_tasks(:running_task) # belongs to `stack`
  task_commands = Shipit::TaskCommands.new(task)
  command = task_commands.perform.first

  assert_equal "true", command.env["PROMPT_COMMAND"],
    "invariant violated: tasks.<name>.steps env must not contain fork-controllable PROMPT_COMMAND key"
end
```
Binding under test: `stack.env.keys` (expected: fixed set from `Stack#env`) `==` `command.env.keys` used by `Command#start`/`PTY.spawn` — the test demonstrates they diverge because `PROMPT_COMMAND` (attacker-chosen) appears on the right side but is not part of the intended fixed set.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L29-31)
```ruby
              requires :labels, Array do
                requires :name, String
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

**File:** lib/shipit/task_commands.rb (L23-27)
```ruby
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
