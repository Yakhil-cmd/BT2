## Analysis

I traced the binding: **does `rollback.override` inherit only Shipit-controlled env keys, or can a PR label name inject arbitrary keys?**

The equality that should hold is:
`Command#env.keys ⊆ (Shipit.env.keys ∪ Stack#env.keys ∪ deploy_spec-derived variable names)`

Tracing the code shows this is **not** the case for `ReviewStack`.

`ReviewStack#env` merges the PR's labels directly, with no allowlist: [1](#0-0) 

The label values themselves are populated straight from the webhook payload with no filtering: [2](#0-1) 

This differs fundamentally from every other env-injection path in the codebase, which is explicitly allowlisted via `EnvironmentVariables#permit`: [3](#0-2) [4](#0-3) [5](#0-4) 

That allowlist (`filter_rollback_envs`/`rollback_params`) only gates **explicitly submitted** override params from a controller action performed by an authenticated user with deploy permission. It is never applied to `ReviewStack#env`'s label-derived hash. That hash instead flows unfiltered through `RollbackCommands#env → DeployCommands#env → TaskCommands#env → Commands#env`, ultimately becoming the `env:` hash passed into `Command.new`: [6](#0-5) [7](#0-6) [8](#0-7) 

This is confirmed as intentional, existing, and tested behavior (not merely theoretical) by the repo's own test suite, which explicitly asserts that arbitrary uppercased PR label names become environment keys reaching `DeployCommands`/`TaskCommands`: [9](#0-8) [10](#0-9) 

### What is and isn't proven

- **Proven, exactly as stated in the invariant**: a fork PR author can, purely by naming a label (e.g. `env`), make an arbitrary uppercase key (e.g. `ENV`) with a fixed value `"true"` appear in the environment of every command run for that review stack, including `rollback.override` steps, with zero allowlist check. This directly contradicts "the `rollback.override` step inherits no fork-controllable key such as `ENV`."
- **Not verified from the available code**: whether the shell that actually executes `rollback.override` steps (via `Command`/`PTY.spawn`) is invoked in a mode that honors a startup-file-sourcing variable named `ENV` (e.g., POSIX `sh`/`dash` running interactively) as opposed to `bash -c` non-interactively, and whether the value is a controllable path (it is hard-coded to the literal string `"true"`, not an attacker-chosen path — the attacker would additionally need to commit a file literally named `true` to their fork for this to have any executable effect). I was unable to fully trace `Command#start`'s exact spawn invocation (shell selection, argv construction) within the available tool budget to confirm or rule out this specific startup-sourcing mechanism.

### Conclusion

The concrete, code-supported finding is **arbitrary environment-key injection from a fork PR label into rollback/deploy process environments, bypassing the engine's own `EnvironmentVariables#permit` allowlisting model** — confirmed by `app/models/shipit/review_stack.rb:84-93` and the existing test coverage. This is a real violation of the stated invariant and a meaningful weakening of the env-allowlisting security boundary (an unprivileged fork PR author can set `RUBYOPT`, `BASH_ENV`-style, or tool-specific env vars — with the caveat that the value is fixed to the string `"true"`, limiting many injection primitives). Whether this specific gap escalates to full RCE via shell-startup-file sourcing depends on `Command#start`'s exact shell-invocation semantics, which I could not fully confirm in this session — I recommend this be checked directly against `lib/shipit/command.rb`'s process-spawning code (not fully captured in the indexed context) before treating it as a proven Critical RCE versus a High-severity env-allowlist-bypass finding.

Given the indexing limits on this file (`lib/shipit/command.rb`'s `start`/spawn method body was not fully returned by search), I'd suggest starting a full Devin session to inspect the complete `Command` class and confirm the exact shell invocation, to close the remaining gap in this analysis before filing the report at Critical severity.

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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
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

**File:** app/controllers/shipit/rollbacks_controller.rb (L29-31)
```ruby
    def rollback_params
      params.require(:rollback).permit(:parent_id, env: @stack.rollback_variables.map(&:name))
    end
```

**File:** lib/shipit/rollback_commands.rb (L1-14)
```ruby
# frozen_string_literal: true

module Shipit
  class RollbackCommands < DeployCommands
    def steps
      deploy_spec.rollback_steps!
    end

    def env
      super.merge(
        'ROLLBACK' => '1'
      )
    end
  end
```

**File:** lib/shipit/deploy_commands.rb (L1-23)
```ruby
# frozen_string_literal: true

module Shipit
  class DeployCommands < TaskCommands
    def steps
      deploy_spec.deploy_steps!
    end

    def env
      commit = @task.until_commit
      super.merge(
        'SHA' => commit.sha,
        'REVISION' => commit.sha,
        'DIFF_LINK' => diff_url
      )
    end

    protected

    def diff_url
      Shipit::GithubUrlHelper.github_commit_range_url(@stack, *@task.commit_range)
    end
  end
```

**File:** lib/shipit/command.rb (L29-37)
```ruby
    attr_reader :out, :chdir, :env, :args, :pid, :timeout

    def initialize(*args, chdir:, default_timeout: Shipit.default_inactivity_timeout, env: {})
      @args, options = parse_arguments(args)
      @timeout = parse_timeout(options['timeout'] || options[:timeout]) || default_timeout
      @env = env.transform_values { |v| v&.to_s }
      @chdir = chdir.to_s
      @timed_out = false
    end
```

**File:** test/lib/shipit/deploy_commands_test.rb (L1-16)
```ruby
# frozen_string_literal: true

require "test_helper"

class DeployCommandsTest < ActiveSupport::TestCase
  test "#env includes the stack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    deploy = stack.trigger_continuous_delivery
    stack.pull_request.labels = ["wip", "bug"]

    env = Shipit::DeployCommands.new(deploy).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
  end
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
