### Title
Unfiltered PR-label environment variables let attackers override `PATH`/`IFS`/`BASH_ENV` in `Command`/`PTY.spawn` for review-stack tasks - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every pull request label name (upcased) into the task's environment with value `"true"`, with no whitelist, and this hash flows unfiltered into `Command#start`'s `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` call. Because `unbundled_env` merges the caller-supplied `@env` *after* it sets a safe `PATH`, an attacker who can label their own PR (e.g. with `PATH`) can fully replace the subprocess's `PATH`, and because the review stack's working directory is a checkout of that same attacker-controlled branch, this yields command-search-path hijacking and RCE on the deploy host.

### Finding Description
The broken binding: `EnvironmentVariables.permit(deploy_spec.machine_env / VariableDefinition allow-list)` == `env keys reaching PTY.spawn`. This holds for `@task.env` (filtered via `filter_deploy_envs`/`filter_rollback_envs` in `app/models/shipit/deploy_spec.rb:174-180` using `EnvironmentVariables#permit`, see `lib/shipit/environment_variables.rb:13-18,35-44`), but it does **not** hold for PR-label-derived env vars.

`ReviewStack#env` (app/models/shipit/review_stack.rb:84-93):
```ruby
def env
  return super unless pull_request.present?
  super.merge(
    pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
  )
end
```
Every label name on the PR becomes an environment key with value `"true"`, with zero filtering against `deploy_variables`/`rollback_variables` or any deny-list of shell-significant names (`IFS`, `PATH`, `ENV`, `BASH_ENV`, `PS4`, `LD_PRELOAD`, etc.). This is confirmed by the existing tests `test/models/shipit/review_stack_test.rb:59-65`, `test/lib/shipit/task_commands_test.rb`, and `test/lib/shipit/deploy_commands_test.rb`, which assert arbitrary label names become env vars.

This flows through `TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`, `.merge(@stack.env)`) into `Command.new(command_line, env:, chdir: steps_directory)` (`lib/shipit/task_commands.rb:24-27`), and finally into `Command#start`:
```ruby
# lib/shipit/command.rb:92, 103-105
@out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
...
def unbundled_env
  BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
end
```
`@env.stringify_keys` is merged **last**, so a label named `PATH` overwrites the safe `PATH` entirely. Since a review stack's task working directory is a checkout of the attacker's own PR branch, the attacker can also commit a malicious executable at a path matching a command invoked by a later deploy/dependency step (e.g. `bundle`, `cap`, `git`) under a directory literally named after the label value (`"true"`). When the shell resolves that command name via the hijacked relative `PATH`, it executes the attacker's script instead of the real binary - full RCE on the deploy host, in the same trust context as the deploy (`GITHUB_TOKEN`, deploy secrets, etc.).

Labels can also be set to shell-significant names such as `IFS` or `BASH_ENV`; whether those achieve code execution depends on which shell interprets `PTY.spawn`'s single-string command (bash vs dash), which is environment-dependent and not something this engine controls - so that specific vector is not reliably demonstrable purely from this codebase. The `PATH`-override vector, however, is deterministic and requires no assumption about the system shell, because `execve`/`PATH` resolution semantics are POSIX-standard regardless of shell.

**Why existing guards fail:** `filter_deploy_envs`/`filter_rollback_envs`/`EnvironmentVariables#permit` are only invoked on `@task.env` (operator-triggered task/deploy variables), never on `@stack.env`/`ReviewStack#env`'s label-derived hash. `verify_signature`/webhook auth is not bypassed — the attacker's action is a legitimate GitHub label event on their own PR/fork, which is exactly the expected trust boundary review stacks are designed to handle, so no forged webhook is required.

### Impact Explanation
An attacker who owns a PR against a repository configured with review stacks can label the PR `PATH` (or `IFS`/`BASH_ENV`, contingent on shell) and commit an executable at the resulting search path inside their own branch. The next review-stack task (`install_dependencies`/`perform`, i.e. dependency install or deploy step) executes with the poisoned `PATH`, causing arbitrary command execution on the Shipit deploy host under the process's privileges - including access to `GITHUB_TOKEN`, deploy-time secrets, and the ability to affect any stack processed by that host. This is repeatable against any repository with review stacks enabled and matches the Critical category: "RCE on the deploy host via `Command`/`PTY.spawn`".

### Likelihood Explanation
Preconditions: the target repository must have Shipit review stacks enabled (a common, documented feature) and no maintainer approval gate before review-stack tasks run for arbitrary PRs (this is by design - review stacks run automatically on PR events). The attacker needs only to open/label a PR from their own fork with a label such as `PATH`, and commit a file at the matching relative path in their branch - all actions available to any unprivileged GitHub user. No secrets, sessions, or privileged roles are required. This is low-cost and repeatable per PR/label event.

### Recommendation
Do not merge raw PR label names into the subprocess environment. Either drop this feature or run label-derived vars through the same `EnvironmentVariables#permit` allow-list used for `deploy_variables`/`rollback_variables`, and additionally hard-deny shell/exec-significant names (`PATH`, `IFS`, `ENV`, `BASH_ENV`, `PS4`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, etc.) regardless of allow-list configuration. In `Command#unbundled_env`, also consider merging `@env` before setting `PATH` (or explicitly disallowing `PATH` overrides from task-provided env) so a caller-supplied env can never fully replace the trusted `PATH`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_env_injection_test.rb
require "test_helper"

module Shipit
  class ReviewStackEnvInjectionTest < ActiveSupport::TestCase
    test "a PR label named PATH overrides Command's PATH env var, unfiltered" do
      stack = shipit_stacks(:review_stack)
      stack.pull_request.labels = ["PATH"]

      env = Shipit::TaskCommands.new(shipit_tasks(:shipit_restart).tap { |t| t.stack = stack }).env

      # Binding under test: env keys reaching PTY.spawn must equal
      # deploy_spec.machine_env / VariableDefinition-permitted keys.
      # It does not: an unpermitted 'PATH' key is present.
      assert_equal "true", env["PATH"]
      refute deploy_spec_permits?(stack, "PATH")
    end

    test "Command#unbundled_env lets caller env fully replace safe PATH" do
      command = Shipit::Command.new("true", env: { "PATH" => "attacker_dir" }, chdir: ".")
      assert_equal "attacker_dir", command.unbundled_env["PATH"]
    end

    private

    def deploy_spec_permits?(stack, key)
      spec = Shipit::DeploySpec::FileSystem.new(stack.deploys_path, stack)
      spec.deploy_variables.map(&:name).include?(key)
    end
  end
end
```
This demonstrates, without any live GitHub interaction, that a PR label reaches `Command#env`/`#unbundled_env` unfiltered by the `deploy_variables`/`VariableDefinition` allow-list, breaking the claimed binding and enabling `PATH` (and potentially `IFS`/`BASH_ENV`) hijacking of subprocess execution in `PTY.spawn`.