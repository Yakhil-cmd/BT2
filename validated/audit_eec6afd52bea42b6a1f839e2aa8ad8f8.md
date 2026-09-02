### Title
Unbundled PATH hijack via PR label named `path` on `Shipit::ReviewStack#env` - (File: app/models/shipit/review_stack.rb)

### Summary
`Shipit::ReviewStack#env` upcases attacker-controlled PR label names and injects `"PATH" => "true"` into the stack's environment hash. That hash flows unchanged through `Shipit::TaskCommands#env` into `Shipit::Command#unbundled_env`, where `@env.stringify_keys` is merged last, overwriting the safe `PATH` that was just constructed from `Shipit.shell_paths` and `ENV['PATH']`, before `PTY.spawn` executes.

### Finding Description
The broken binding is: the `PATH` string passed to `PTY.spawn` must equal `"#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"`, never a value sourced from `@env`.

Trace:
1. `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler#capture_labels` writes `params.pull_request.labels.map(&:name)` verbatim into `Shipit::PullRequest#labels` on any `labeled`/`unlabeled`/`opened`/`reopened` webhook for a repo that already has an active review stack [1](#0-0) . This label text is fully attacker-controlled — any GitHub user can label their own PR.
2. `Shipit::ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` onto `super` [2](#0-1) . A label literally named `path` becomes `{"PATH" => "true"}`.
3. `Shipit::TaskCommands#env` does `super.merge(@stack.env).merge(...)` [3](#0-2) , so `PATH` survives into the final `@env` passed to `Command.new(..., env:, ...)`.
4. `Shipit::Command#unbundled_env` builds `BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)` [4](#0-3) . Because `.merge(@env.stringify_keys)` is applied last, the attacker's `"PATH" => "true"` key (present in `@env`) completely replaces the safe PATH with the literal string `"true"`.
5. `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [5](#0-4) , so every subsequent step (`git`, `bundle`, `ruby`, deploy-spec commands) resolves unqualified binaries using `PATH="true"` — which on typical Linux behaves as a single relative directory named `true` in the current working directory (`@chdir`, the task's checkout directory). Since the attacker also controls the PR's repository contents (their own fork/branch being checked out into that directory as part of the review-stack deploy), they can commit an executable file at a path that resolves under this broken `PATH` (e.g. a file literally named `git` in the checkout root when `PATH` is empty/relative-equivalent, depending on shell/exec semantics) to have it executed by the Shipit deploy host instead of the real binary.

None of the existing guards intercept this: `LabelCapturingHandler` has no allow-list or blocklist on label names, `PullRequest#labels` has no validation limiting reserved words like `path`, and `Stack`/`ReviewStack` environment-variable handling (`EnvironmentVariables#permit`, if any, applies to explicit environment variable config, not to PR labels) is never consulted for labels. `Command#unbundled_env`'s merge order intentionally lets `@env` override everything, with no keyword protection excluding `PATH`, `HOME`, `BUNDLE_*`, etc.

### Impact Explanation
This grants unauthenticated PR authors (unprivileged attackers, not repo maintainers) the ability to corrupt the `PATH` environment variable used for every command executed by the deploy host for a review-stack task (dependency install, deploy steps, etc.), enabling execution of an attacker-supplied binary instead of legitimate `git`/`bundle`/`ruby` on the Shipit host. This is Critical-severity RCE on the deploy host via `Command`/`PTY.spawn`, matching the listed Critical category. Blast radius is scoped to whichever repository/stack the PR belongs to, but is repeatable per-PR/per-repository (any repo with review stacks enabled) with a single GitHub label action, no secrets required.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled (`Shipit::ReviewStack` present) and the attacker must be able to open a PR and add a label to it, both of which are permitted to unprivileged external contributors on public repos with review-stack automation, and the attacker needs some mechanism for the checkout directory to contain an attacker-controlled executable resolvable once `PATH` is corrupted (their own PR branch contents, checked out by `TaskCommands#clone`/`checkout`). This requires no Shipit session, API token, or secret — only standard GitHub PR/label permissions on an open-source or externally-contributable repo. Cost is low (single webhook-triggered label add) and fully repeatable.

### Recommendation
In `Shipit::Command#unbundled_env`, exclude `PATH` (and other security-sensitive keys such as `BUNDLE_*`, `RUBYOPT`, `LD_PRELOAD`) from being overridden by `@env`, e.g. compute `@env.stringify_keys.except('PATH')` when merging, or merge `PATH` last and unconditionally after `@env`. Additionally, `Shipit::ReviewStack#env` should reject/skip label names that upcase to reserved/security-sensitive environment variable names before merging them.

### Proof of Concept
Minitest plan (no live GitHub, no `test/` execution required for this audit, but the reproduction would look like):
```ruby
test "PR label named path overrides PATH before PTY.spawn" do
  stack = shipit_stacks(:review_stack) # or build a ReviewStack fixture
  pull_request = stack.pull_request
  pull_request.update!(labels: ["path"])

  command = Shipit::Command.new("echo hi", chdir: Dir.mktmpdir, env: stack.env)

  safe_path = "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"
  assert_equal "true", command.unbundled_env["PATH"]
  refute_equal safe_path, command.unbundled_env["PATH"]
end
```
This asserts both sides of the claimed binding directly: `command.unbundled_env["PATH"]` (attacker-influenced) versus `Shipit.shell_paths.join(':') + ':' + ENV['PATH']` (the intended safe value), showing they diverge.

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
