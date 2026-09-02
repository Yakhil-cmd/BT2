## Title
Attacker-controlled PR label named `PATH` overrides the sanitized `PATH` used to spawn deploy commands - (File: `lib/shipit/command.rb`)

## Summary
`Shipit::ReviewStack#env` upcases every PR label name and injects it verbatim as an environment-variable key with value `"true"`, with no denylist against reserved keys like `PATH`. That hash flows unfiltered through `TaskCommands#env` into `Command#unbundled_env`, where it is merged **after** the deliberately-sanitized `PATH`, letting an attacker overwrite the process `PATH` used by `PTY.spawn`.

## Finding Description
The binding that should hold is: `pull_request.labels.map(&:upcase) ∩ {PATH, GIT_ASKPASS, BUNDLE_PATH, RUBYOPT, LD_PRELOAD, GIT_SSH_COMMAND} == ∅`, i.e. label-derived keys should never collide with security-relevant env vars that reach `PTY.spawn`. This binding is violated for `PATH`.

Trace:
- `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` onto `PullRequest#labels` with no filtering: [1](#0-0) 
- `Shipit::ReviewStack#env` merges `labels.each_with_object({}) { |n,h| h[n.upcase] = "true" }` over `super`, again with no denylist on the resulting keys: [2](#0-1) 
- `TaskCommands#env` merges `@stack.env` early, then a fixed hash of explicit keys (`BUNDLE_PATH` is one of these, so it is protected), then `deploy_spec.machine_env`, then `@task.env` — but it never re-asserts `PATH`, so a label-derived `PATH` key survives unmodified to the end of this chain if the repo's `shipit.yml` (`machine.environment`) or the task's own `env` doesn't also set `PATH`: [3](#0-2) 
- `Command#unbundled_env` computes the intended sanitized `PATH` (`Shipit.shell_paths` + system `PATH`) and then **merges `@env.stringify_keys` on top of it**, so any `PATH` key present in the caller-supplied `env` (which includes the label-derived hash) silently overrides the sanitized value: [4](#0-3) 
- This merged env is passed directly to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`: [5](#0-4) 

Root cause: neither `ReviewStack#env` nor `TaskCommands#env` denylists reserved environment-variable names before merging attacker-controlled label data into the environment that eventually reaches process spawning.

However, the *value* the attacker can inject is not arbitrary. `ReviewStack#env` always maps every label to the fixed string literal `"true"` (`labels[label_name.upcase] = "true"`) — the attacker only controls which **key** is set, not its value. So the practical effect of naming a label `PATH` is that the final `unbundled_env['PATH']` becomes the literal string `"true"`, not an attacker-chosen path string. Achieving RCE from this would additionally require the attacker to control a relative directory literally named `true` inside the checked-out working directory (`@task.working_directory`, which is `chdir` for `PTY.spawn`) containing malicious executables named after commands actually invoked during deploy (e.g. `git`, `bundle`, `cap`), since a `PATH` of `"true"` with no absolute directories would only resolve executables relative to `chdir`.

I was unable to fully verify, within the available context, whether review-stack deploys for genuine **fork** PRs actually check out the fork's branch content into `@task.working_directory` (the `git fetch`/`git clone` calls in `StackCommands` use `@stack.branch` against the `origin` remote of the stack's own git cache, and `ReviewStackAdapter#stack_attributes` sets `branch: params.pull_request.head.ref` — a bare ref name with no indication of fork-remote wiring). If review-stack branch checkout requires the branch to exist in the base repository's own remote (i.e., only same-repo PRs, not true external forks, are supported), then the "attacker pushes malicious content to `chdir/true/`" leg of the exploit chain would not be reachable for an unprivileged external fork attacker as claimed in the prompt's threat model. This is a genuine engine-config-dependent gap I could not close with the tools available.

## Impact Explanation
At minimum, this is a reliable **environment-corruption/PATH-clobbering bug**: any PR labeled `PATH` (or `GIT_COMMITTER_NAME`, `EMAIL`, `TASK_ID`, `IGNORED_SAFETIES`, `SHIPIT_LINK`, `SHIPIT_USER`, etc. — any key not re-asserted after `@stack.env` is merged, and `PATH` specifically since `unbundled_env` never re-sanitizes it) will corrupt the deploy command's environment, breaking or altering deploy execution for that stack's tasks. Whether this reaches the "Critical - RCE" bar depends on whether the attacker can also control file content at `chdir/true/*` in the checked-out working tree, which in turn depends on repo/fork wiring I could not fully confirm from available files. If that additional precondition holds, it is Critical RCE on the deploy host scoped to the stack being deployed; if not, the practical impact is corruption of `PATH` (denial/breakage of deploy commands) for that stack, which does not meet the "Critical" bar defined in the rules (RCE, auth bypass, credential exfiltration, cross-tenant mutation) on its own.

## Likelihood Explanation
Preconditions per the prompt are satisfiable by an unprivileged actor: `review_stacks_enabled` + `provisioning_behavior: allow_all` on the target repository, opening a PR, and adding a label literally named `PATH` (case-insensitive, since it's upcased) — all attacker-controlled free text with no server-side denylist. The label capture path (`LabelCapturingHandler`) requires no authentication beyond a normal signed webhook from GitHub reflecting the attacker's own PR action, which is by design unauthenticated content the repo owner already opted into ingesting via `allow_all`.

## Recommendation
- In `Shipit::ReviewStack#env`, reject or drop label-derived keys that collide with a denylist of reserved/security-relevant environment variable names (`PATH`, `BUNDLE_PATH`, `GIT_ASKPASS`, `RUBYOPT`, `LD_PRELOAD`, `GIT_SSH_COMMAND`, etc.) before merging.
- In `Shipit::Command#unbundled_env`, re-assert the sanitized `PATH` (and other security-critical vars) **after** merging `@env`, rather than before, so caller-supplied env can never override them: `BASE_ENV.merge(@env.stringify_keys).merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}")`.
- Consider prefixing label-derived environment variables (e.g. `SHIPIT_LABEL_<NAME>`) instead of writing raw uppercased label names directly into the process environment namespace.

## Proof of Concept
Minitest plan (`test/models/shipit/review_stack_test.rb` / `test/lib/shipit/task_commands_test.rb` / `test/unit/command_test.rb` style):
```ruby
test "#env: a label named PATH clobbers the sanitized PATH reaching PTY.spawn" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["PATH"]

  # 1. ReviewStack#env sets the reserved key
  assert_equal "true", stack.env["PATH"]

  # 2. TaskCommands#env propagates it unchanged
  task = shipit_tasks(:shipit_restart)
  task.stack = stack
  task_env = Shipit::TaskCommands.new(task).env
  refute_equal "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}", task_env["PATH"]
  assert_equal "true", task_env["PATH"]

  # 3. Command#unbundled_env is clobbered, this is what reaches PTY.spawn
  command = Shipit::Command.new("echo hi", env: task_env, chdir: Dir.tmpdir)
  assert_equal "true", command.unbundled_env["PATH"]
  refute_includes command.unbundled_env["PATH"], Shipit.shell_paths.join(':')
end
```
This proves the equality-violation chain end-to-end without live GitHub, using only stubbed fixtures (`shipit_stacks(:review_stack)`, `shipit_tasks(:shipit_restart)`) already used by existing tests such as `test/models/shipit/review_stack_test.rb:59-65` and `test/lib/shipit/task_commands_test.rb:6-16`.

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
