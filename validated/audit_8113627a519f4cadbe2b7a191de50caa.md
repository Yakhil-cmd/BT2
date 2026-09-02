### Title
Unfiltered PR label names and `machine.environment` become raw process environment keys reaching `PTY.spawn`, allowing `PERL5OPT`/`RUBYOPT`/`LD_PRELOAD`-style env injection on review-stack tasks - ([File: app/models/shipit/review_stack.rb], [File: lib/shipit/command.rb])

### Summary
`ReviewStack#env` turns every GitHub PR label name into a raw environment-variable key (uppercased, value `"true"`) with no allowlist, and `DeploySpec#machine_env` passes `shipit.yml`'s `machine.environment` through unfiltered as well. Both are merged into `TaskCommands#env` and ultimately into `Command#unbundled_env`, which performs no key filtering before calling `PTY.spawn`. An unprivileged fork PR author can self-label their own PR (e.g., with a label literally named `PERL5OPT`), and, once a ReviewStack is provisioned/tasked, that key-value pair is injected verbatim into every spawned process's environment for that stack.

### Finding Description
The broken binding: for every key `k` that reaches `Command#unbundled_env`/`PTY.spawn`, `k` should be constrained by an operator-defined allowlist — exactly as the codebase already does for user-triggered deploy/rollback params via `DeploySpec#filter_deploy_envs`/`filter_rollback_envs`, which call `EnvironmentVariables.with(env).permit(variable_definitions)` (`app/models/shipit/deploy_spec.rb:174-180`, `lib/shipit/environment_variables.rb:13-18`). That equality does **not** hold for two other env-merging code paths used by review stacks:

1. `ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`):
```ruby
def env
  return super unless pull_request.present?
  super.merge(
    pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
  )
end
``` [1](#0-0) 
Every PR label name is converted directly into an environment variable key with no call to `EnvironmentVariables#permit` and no denylist.

2. `DeploySpec#machine_env` (`app/models/shipit/deploy_spec.rb:69-71`):
```ruby
def machine_env
  config('machine', 'environment') || {}
end
``` [2](#0-1) 
This reads `shipit.yml`'s `machine.environment` map verbatim, again with no `permit` call.

Both flow into `TaskCommands#env` unfiltered:
```ruby
def env
  super
    .merge(@stack.env)
    .merge(...)
    .merge(deploy_spec.machine_env)
    .merge(@task.env)
end
``` [3](#0-2) 

That merged hash becomes `Command#env`, and `Command#unbundled_env` merges it into the base process env with no key filtering at all:
```ruby
def unbundled_env
  BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
end
``` [4](#0-3) 
which is then passed directly to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` at `Command#start` (`lib/shipit/command.rb:92`). [5](#0-4) 

Reachability: with `provisioning_behavior=prevent_with_label`, opening a PR without the opt-out label auto-provisions a ReviewStack for an unprivileged fork PR (confirmed by `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb:159-172`, `"create stacks for repos what prevent_with_label when label is absent"`). [6](#0-5) 
The attacker then adds a self-owned PR label named `PERL5OPT` (or `perl5opt`, upcased by the code). This label is captured into `pull_request.labels` via the labeled webhook (`LabeledHandler`), and on any subsequent task/review-check run on that stack, `ReviewStack#env['PERL5OPT'] = "true"` is merged straight through to `PTY.spawn`'s environment. Because `PERL5OPT` is honored by the Perl interpreter at process startup (injecting `-M`/`-d` style options), any perl invocation anywhere in the deploy/dependency/review toolchain (common in native-extension builds, `openssl`/build scripts, etc.) inherits attacker-controlled interpreter flags.

Existing guards that fail to stop this: `EnvironmentVariables#permit` exists and is applied to `filter_deploy_envs`/`filter_rollback_envs` (user-submitted deploy variables), but is never applied to `ReviewStack#env`'s label-derived keys nor to `DeploySpec#machine_env`. `verify_signature`/webhook auth is irrelevant here since labeling one's own PR is a legitimate, unauthenticated-from-Shipit's-perspective action available to any PR author.

### Impact Explanation
An unprivileged fork PR author can inject arbitrary environment-variable keys (not just values) into every process spawned for their review stack's tasks (dependency install, deploy steps, review checks). Via keys like `PERL5OPT` (or other interpreter-startup-honored variables such as `RUBYOPT`, `PYTHONSTARTUP`, `LD_PRELOAD` if such interpreters are invoked in the toolchain), this can escalate to arbitrary code execution on the Shipit deploy host under whatever context those tasks run — matching the Critical "RCE on the deploy host via `Command`/`PTY.spawn`" category. Blast radius is scoped to the specific ReviewStack's working directory/host context per this path, but it is entirely attacker-repeatable: any fork PR against a `prevent_with_label` repository can re-trigger tasks (re-push, close/reopen, re-label) to retry the injection.

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled` with `provisioning_behavior = prevent_with_label` (a supported, documented configuration, not an edge case) and the deploy/review toolchain must at some point invoke `perl` (or another interpreter reading a similarly dangerous env var) — common in Ruby/native-extension or general build environments. Attacker cost is minimal: open a PR, add a label named `PERL5OPT` to their own PR. No secrets, tokens, or special GitHub permissions are required — labeling one's own PR is standard PR-author capability. This is fully repeatable per PR/per task run.

### Recommendation
Apply `EnvironmentVariables.with(...).permit(allowlist)` (or an explicit denylist of dangerous keys) to both `ReviewStack#env`'s label-derived hash and `DeploySpec#machine_env` before merging into `TaskCommands#env`/`Command#env`, exactly as is already done for `filter_deploy_envs`/`filter_rollback_envs`. At minimum, reject/strip well-known dangerous interpreter-control variables (`PERL5OPT`, `RUBYOPT`, `PYTHONSTARTUP`, `LD_PRELOAD`, `NODE_OPTIONS`, etc.) from any environment hash whose keys originate from attacker-controllable input (PR labels, PR-branch `shipit.yml`).

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (new test)
test "PR labels inject arbitrary environment variable keys unfiltered" do
  stack = create_review_stack # or shipit review stack fixture
  stack.pull_request.update!(labels: ["PERL5OPT"])

  # Binding under test: for all k in stack.env.keys, k must be in an allowlist.
  # Actual: no allowlist is applied.
  assert_equal "true", stack.env["PERL5OPT"]

  task_commands = Shipit::TaskCommands.new(some_task_on(stack))
  assert_equal "true", task_commands.env["PERL5OPT"]

  command = Shipit::Command.new("true", env: task_commands.env, chdir: ".")
  assert_equal "true", command.unbundled_env["PERL5OPT"]
end
```
This demonstrates the full chain: attacker-controlled PR label -> `ReviewStack#env` -> `TaskCommands#env` -> `Command#unbundled_env`, with no filtering step in between, confirming the divergence from the expected allowlist-enforced binding.

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

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
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

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L159-172)
```ruby
          test "create stacks for repos what prevent_with_label when label is absent" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] = []

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end
```
