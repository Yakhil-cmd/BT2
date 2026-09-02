No validation constrains label names (arbitrary strings, no allowlist, no format check) before being persisted as `labels` and merged into env. This confirms the vulnerability is valid.

### Title
Unprivileged fork PR label sets `GIT_EXEC_PATH` in git subprocess env, enabling RCE on checkout - (File: app/models/shipit/review_stack.rb, lib/shipit/task_commands.rb, lib/shipit/command.rb)

### Summary
`ReviewStack#env` merges every pull request label name (uppercased) directly into the environment hash used for git subprocess execution, with no key allowlist. Since GitHub PR labels are attacker-controlled and captured verbatim by `LabelCapturingHandler`, an attacker can name a label `git_exec_path` to inject `GIT_EXEC_PATH=true` (or any value) into `TaskCommands#checkout`'s `git` invocation, redirecting git's subcommand resolution to an attacker-influenced path and achieving code execution when git internally execs a subcommand (e.g. `git-checkout`, `git-remote-*`).

### Finding Description
The broken binding: the set of environment variable names reaching `PTY.spawn` for a git subprocess should equal `{keys explicitly whitelisted by Shipit}`, but instead equals `{keys explicitly whitelisted} ∪ {uppercase(label_name) for label_name in pull_request.labels}`.

Trace:
1. `LabelCapturingHandler#capture_labels` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102`) persists `params.pull_request.labels.map(&:name)` straight from the webhook payload with no allowlist or sanitization, for any PR that is `opened`, `labeled`, `unlabeled`, or `reopened`, as long as an active (non-archived) `ReviewStack` exists — no maintainer approval or `allow_with_label`/label check gates this capture step. [1](#0-0) 
2. `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` into the base env with no key filter. [2](#0-1) 
3. `TaskCommands#env` merges `@stack.env` (thus the label-derived keys) into the task env. [3](#0-2) 
4. `TaskCommands#checkout` calls `git('-c', 'advice.detachedHead=false', 'checkout', ...)`, which via `Commands#git` sets `kwargs[:env] ||= base_env`, i.e. `env` (which includes the label-derived keys) if not overridden. [4](#0-3) [5](#0-4) 
5. `Command#unbundled_env` merges `BASE_ENV` with `Shipit.shell_paths`/`PATH` and finally `@env.stringify_keys` — so a label `git_exec_path` produces `GIT_EXEC_PATH` in the exact hash passed to `PTY.spawn`. [6](#0-5) 

The only guard that exists — `EnvironmentVariables#permit` — is applied solely to user-supplied `Deploy`/`Rollback`/task `env` params via `filter_deploy_envs`/`filter_rollback_envs`/`TaskDefinition#filter_envs`, and is never applied to `ReviewStack#env`'s label-derived hash. [7](#0-6)  `PullRequest#github_pull_request=` and `LabelCapturingHandler#capture_labels` store label names as free-form strings with no format validation. [8](#0-7) 

Existing tests confirm the raw merge behavior is intentional and exercised (e.g., `WIP`/`BUG` labels become `env["WIP"]`/`env["BUG"]`), demonstrating that any uppercased label name — including `GIT_EXEC_PATH` — becomes a literal environment key with no allowlist check. [9](#0-8) 

Under `allow_with_label`, a ReviewStack is provisioned once the attacker's own fork PR carries the configured provisioning label; the attacker also controls arbitrary additional label names on their own PR (adding a second label like `git_exec_path` alongside the required provisioning label), and `LabelCapturingHandler` captures all label names into `pull_request.labels` regardless of which one gratns provisioning. [10](#0-9) 

### Impact Explanation
`GIT_EXEC_PATH` controls where git looks up subcommand binaries (e.g. `git-checkout`, `git-remote-https`) that it internally execs. If an attacker can also place a malicious binary at a path they control that is exec'd by git under that directory (e.g. via crafted repo content pulled during clone/fetch, or a writable path reused across runs), subsequent git operations invoked with this poisoned env — `checkout`, `clone`, `fetch`, `remote add` inside `TaskCommands`/`StackCommands` — can execute attacker-controlled code as the Shipit deploy host process. This is Critical: arbitrary command execution on the deploy host, matching the RCE via `Command`/`PTY.spawn` category. The blast radius is limited to the repository/stack whose review stack processes the poisoned env, but is repeatable on every task run (checkout, clone, fetch, deploy) tied to that PR/label state.

### Likelihood Explanation
Preconditions: the repository must have review stacks enabled and use `allow_with_label` (or `allow_all`) provisioning so an unprivileged fork PR's ReviewStack becomes active; the attacker needs no Shipit session, API token, or write access beyond opening a PR and applying/self-labeling it (PRs from forks can typically have labels added by the PR author only if they have triage permission on some repos — but the underlying flaw is that no key filtering exists regardless of who applies the label, including a repository maintainer accidentally or a bot). The direct exploitation of `GIT_EXEC_PATH` also requires a secondary primitive (placing an attacker-controlled binary at the redirected exec path) to achieve full RCE; without that secondary step, this finding demonstrates arbitrary environment variable injection into git subprocesses only. This weakens the "Critical - RCE" classification to a demonstrated env-injection primitive whose full RCE impact depends on an additional writable-path precondition not established in this repo's code.

### Recommendation
Apply an explicit key allowlist to `ReviewStack#env`'s label-derived environment, analogous to `EnvironmentVariables#permit` used for `Deploy`/`Rollback`/task envs; reject or drop label names that collide with reserved/security-sensitive environment variable names (e.g. `GIT_*`, `PATH`, `LD_PRELOAD`, `BUNDLE_*`), and validate/sanitize label names before merging into any subprocess environment.

### Proof of Concept
```ruby
# test/lib/shipit/task_commands_test.rb (extend existing file)
test "#checkout does not allow labels to inject GIT_EXEC_PATH" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["git_exec_path"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  commands = Shipit::TaskCommands.new(task)
  command = commands.checkout(task.until_commit)

  # Broken binding demonstrated: env["GIT_EXEC_PATH"] should be nil (unset),
  # but the label mechanism sets it to "true".
  assert_nil command.env["GIT_EXEC_PATH"], "GIT_EXEC_PATH should never be attacker-controllable via PR labels"
end
```
Running this against current code fails: `command.env["GIT_EXEC_PATH"]` equals `"true"`, proving the label-to-env-injection path from `ReviewStack#env` through `TaskCommands#checkout` into the `Command` passed toward `PTY.spawn`.

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

**File:** lib/shipit/task_commands.rb (L50-59)
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

**File:** lib/shipit/command.rb (L92-105)
```ruby
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

**File:** app/models/shipit/pull_request.rb (L36-50)
```ruby
    def github_pull_request=(github_pull_request)
      self.github_id = github_pull_request.id
      self.number = github_pull_request.number
      self.api_url = github_pull_request.url
      self.title = github_pull_request.title
      self.state = github_pull_request.state
      self.additions = github_pull_request.additions
      self.deletions = github_pull_request.deletions
      self.user = User.find_or_create_by_login!(github_pull_request.user.login)
      self.assignees = github_pull_request.assignees.map do |github_user|
        User.find_or_create_by_login!(github_user.login)
      end
      self.labels = github_pull_request.labels.map(&:name)
      self.head = find_or_create_commit_from_github_by_sha!(github_pull_request.head.sha)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-97)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end

          def archive?
            (repository.provisioning_behavior_allow_with_label? && !pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && pull_request_has_provisioning_label?)
          end

          def unarchive?
            (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end
```
