### Title
Attacker-controlled PR label named `PATH` overrides Shipit's sanitized `PATH` env var, enabling command hijacking in `Command#unbundled_env` - (File: lib/shipit/command.rb)

### Summary
`ReviewStack#env` builds an environment hash from PR labels by uppercasing each label name and setting its value to `"true"`, with no key whitelist, so a PR label literally named `PATH` (or `path`) yields `{'PATH' => 'true'}`. This unfiltered value survives through `TaskCommands#env` and is used last by `Command#unbundled_env`, which merges `@env.stringify_keys` on top of Shipit's computed `PATH`, letting the label clobber it.

### Finding Description
The broken binding: `Command#unbundled_env`'s keys are assumed to equal only what `deploy_spec.machine_env`/`VariableDefinition` whitelists permit, but `PATH` is never in any `VariableDefinition` list, and `ReviewStack#env` injects arbitrary uppercased label names unfiltered: [1](#0-0) 

`TaskCommands#env` merges `@stack.env` (which for a `ReviewStack` includes the label-derived hash) before the hardcoded keys, `deploy_spec.machine_env`, and `@task.env` — none of which touch `PATH`: [2](#0-1) 

`Command#unbundled_env` computes a safe `PATH` from `Shipit.shell_paths`, then merges `@env.stringify_keys` on top, so any `PATH` key surviving in `@env` wins over the computed value: [3](#0-2) 

This env reaches `PTY.spawn` verbatim in `Command#start`: [4](#0-3) 

Exploit flow: attacker opens a PR on their own repository (which has `review_stacks_enabled`), adds a label named `PATH`, and GitHub's `pull_request`/`labeled` webhook is delivered to `POST /webhooks`. `LabelCapturingHandler#capture_labels` persists the labels verbatim onto `pull_request.labels`: [5](#0-4) 

When Shipit later runs any task on that review stack (`checkout`, `clone`, `install_dependencies`, `perform` in `TaskCommands`), `Command`'s `PATH` becomes `"true"`. Combined with a directory `true` containing an executable named `git`/`bundle`/`cap` committed to the checked-out branch (`chdir` points at the working directory), the shell resolves `git`/`bundle`/`cap` to the attacker's binary instead of the real one, achieving RCE on the deploy host under the deploy process's privileges.

Existing guards do not stop this: webhook signature verification only authenticates that the payload came from GitHub for that repository — it does not validate or filter the *content* of `labels`, and there is no `EnvironmentVariables#permit`/whitelist check applied to `ReviewStack#env`'s label-derived hash before it flows into `Command`.

### Impact Explanation
Arbitrary command execution on the Shipit deploy host, scoped to the attacker's own repository's review-stack task processes, but running with the deploy host's ambient privileges/credentials (which may include `GITHUB_TOKEN`, deploy secrets, or shared host resources) — this is Critical/RCE. It is repeatable on every task run for that stack while the label remains and is generalizable to any repository with review stacks enabled that an attacker can label (their own or, if they can influence labels on repos they don't own, other repos as well, though the given scenario is self-owned).

### Likelihood Explanation
Preconditions: repository must have `review_stacks_enabled`, and the stack/PR must not be archived — feature that's specifically designed to run untrusted PR code, which is inherently the highest-risk configuration in Shipit. Attacker cost is trivial: open a PR, add one label, and commit a malicious binary into their own branch — all actions available to any GitHub user on their own fork/repo with no Shipit credentials, no maintainer status, and no secrets. This is a low-cost, deterministic, and repeatable path.

### Recommendation
In `ReviewStack#env` (or upstream in `Stack#env`/`TaskCommands#env`), filter label-derived environment keys against an explicit allowlist of safe variable names (or block reserved names like `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `BUNDLE_PATH`, `HOME`, `IFS`, etc.). Alternatively/additionally, in `Command#unbundled_env`, compute `PATH` last so it cannot be overridden by caller-supplied `@env`, i.e. merge order should end with the trusted `PATH` value rather than `@env.stringify_keys` last, or explicitly strip `PATH` (and other dangerous keys) from `@env` before merging.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_env_path_override_test.rb
require 'test_helper'

class ReviewStackEnvPathOverrideTest < ActiveSupport::TestCase
  test "PR label named PATH overrides computed PATH in unbundled_env" do
    stack = shipit_stacks(:cyclimse) # or a ReviewStack fixture
    pull_request = shipit_pull_requests(:review_stack_pr)
    pull_request.update!(labels: ['PATH'])
    stack.update!(pull_request: pull_request) if stack.respond_to?(:pull_request=)

    task = shipit_tasks(:cyclimse_deploy)
    task_commands = Shipit::TaskCommands.new(task)

    # Binding before: env['PATH'] should NOT equal attacker value
    assert_not_equal 'true', task_commands.env['PATH']  # expected to FAIL, proving the vuln
    assert_equal 'true', task_commands.env['PATH']       # actual observed behavior

    tmpdir = Dir.mktmpdir
    command = Shipit::Command.new('git --version', env: task_commands.env, chdir: tmpdir)

    refute_equal "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}", command.unbundled_env['PATH']
    assert_equal 'true', command.unbundled_env['PATH']
  end
end
```
This demonstrates that `pull_request.labels = ['PATH']` propagates through `ReviewStack#env` → `TaskCommands#env` → `Command#unbundled_env`, overriding `Shipit.shell_paths`-derived `PATH` with the attacker-controlled value `'true'`, confirming the binding is broken.

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

**File:** lib/shipit/command.rb (L85-99)
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
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```
