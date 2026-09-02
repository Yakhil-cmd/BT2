## Confirmed vulnerability

`chdir` for step execution (`steps_directory`, `lib/shipit/task_commands.rb:92-98`) resolves to `@task.working_directory` — the checked-out contents of the fork PR branch — and `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` (`lib/shipit/command.rb:92`). Because arguments are passed as an argv array (not a shell string), Ruby's `Process.spawn`/`execvp` semantics resolve a bare command name (`pip`) by searching the directories listed in `PATH`, relative to `chdir` for any non-absolute entry. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

### Title
`PATH` hijack via uppercased pull-request label enables RCE in `pip install -r requirements.txt` step - (File: `app/models/shipit/review_stack.rb`, `lib/shipit/command.rb`)

### Summary
`ReviewStack#env` merges every pull-request label (uppercased, with a hard-coded value of `"true"`) into the environment with no key allowlist. `Command#unbundled_env` merges this untrusted env hash *after* it computes `PATH`, so a label literally named `path` overwrites `PATH` with the literal string `"true"` — a relative directory name resolved against `chdir`, which is the attacker's own checked-out fork branch. A fork PR author can plant an executable at `true/pip` in their own branch and label the PR `path`; when the review-stack deploy runs `pip install -r requirements.txt`, `execvp`-style PATH search finds and executes the attacker's binary instead of the real `pip`.

### Finding Description
The broken binding: `Command#unbundled_env` is supposed to guarantee `PATH = "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"` for every spawned process, but instead computes:
```
BASE_ENV.merge('PATH' => "...").merge(@env.stringify_keys)
```
(`lib/shipit/command.rb:103-105`), so any `PATH` key present in `@env` silently overrides the trusted value with no validation. `@env` for a review-stack task step originates from `TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`), which merges `@stack.env`, i.e. `ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`):
```ruby
def env
  return super unless pull_request.present?
  super.merge(pull_request.labels.each_with_object({}) { |n, h| h[n.upcase] = "true" })
end
```
There is no allowlist filtering these merged label-derived keys (unlike `EnvironmentVariables#permit`, `TaskDefinition#filter_envs`, `DeploySpec#filter_deploy_envs`/`filter_rollback_envs`, which are only applied to *user-submitted API/form* env params, not to this label-derived merge).

Exploit flow:
1. Attacker forks the repo, opens a PR, and adds a label named `path` (case-insensitive; upcased to `PATH`) to their own PR. `LabelCapturingHandler#capture_labels` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102`) persists this straight from the webhook payload with no name filtering.
2. Attacker commits an executable file at the relative path `true/pip` inside their fork branch.
3. Shipit auto-creates/updates the `ReviewStack` for the PR and checks out the fork branch into `@task.working_directory`.
4. When a step like `pip install -r requirements.txt` runs, `steps_directory` (`lib/shipit/task_commands.rb:92-98`) sets `chdir` to that checked-out directory, and `env['PATH']` is now `"true"` (a single relative directory).
5. `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` performs an `execvp`-style PATH lookup for the bare command `pip`, finds `./true/pip` relative to `chdir`, and executes the attacker's payload with the deploy host's privileges — RCE.

Existing guards do not prevent this: `verify_signature`/webhook auth only ensure the webhook truly comes from GitHub for that repo, not that label content is safe; `ExplicitParameters` only validates types/shape (`String` for label `name`), not content; and `EnvironmentVariables#permit` is never invoked on the `ReviewStack#env` label merge.

### Impact Explanation
Full remote code execution on the Shipit deploy host, triggered purely by opening a PR from a fork and applying a self-controlled label plus a file in the attacker's own branch — no maintainer approval or elevated privileges required. Because `ReviewStack`s are commonly configured to run automatically on `opened`/`labeled` PR events, this is repeatable per PR/per repository that has review stacks enabled with a `pip install -r requirements.txt` (or any bare-command) step, and matches the Critical "RCE on the deploy host via `Command`/`PTY.spawn`" category.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled (`allow_all` or `allow_with_label` provisioning) and a deploy spec step invoking a bare command name (e.g., `pip install -r requirements.txt`). Given these common conventions, attacker cost is minimal — opening a PR, adding a label, and committing a file are all actions available to any external contributor with fork/PR access. No secrets, tokens, or maintainer interaction required, making this highly feasible and repeatable.

### Recommendation
In `Command#unbundled_env`, either reserve `PATH` (and other security-sensitive keys) so it cannot be overridden by caller-supplied `@env`, e.g. merge the PATH assignment *after* `@env`, or explicitly strip disallowed keys (`PATH`, `LD_PRELOAD`, `IFS`, etc.) from any environment sourced from `ReviewStack#env`. Additionally, apply an explicit allowlist/denylist to `ReviewStack#env`'s label-derived hash (reject reserved/uppercase system env names, or prefix label-derived keys, e.g. `LABEL_<NAME>`) before merging into task/deploy env.

### Proof of Concept
```ruby
# test/unit/command_test.rb (new test)
test "#unbundled_env does not let injected env override PATH" do
  command = Command.new('pip install -r requirements.txt', env: { 'PATH' => 'true' }, chdir: '.')
  refute_equal 'true', command.unbundled_env['PATH']
end

# test/lib/shipit/task_commands_test.rb (new test)
test "#env label named 'path' overrides PATH for spawned command" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["path"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env
  assert_equal "true", env["PATH"]

  command = Shipit::Command.new('pip install -r requirements.txt', env:, chdir: task.working_directory)
  assert_equal "true", command.unbundled_env["PATH"]
end
```
Both assertions should currently pass (demonstrating the injected env value reaches `unbundled_env`'s `PATH`), confirming the binding is broken; a correct fix would make these assertions fail.

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

**File:** lib/shipit/task_commands.rb (L90-98)
```ruby
    protected

    def steps_directory
      if sub_directory = deploy_spec.directory.presence
        File.join(@task.working_directory, sub_directory)
      else
        @task.working_directory
      end
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
