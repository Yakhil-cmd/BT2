### Title
Unfiltered PR label merge into deploy environment allows arbitrary env var injection reaching `PTY.spawn` - (File: app/models/shipit/review_stack.rb)

### Summary
`Shipit::ReviewStack#env` unconditionally merges every GitHub label on the tracked pull request into the process environment used for deploy commands, with the label name upcased and used verbatim as the environment variable key. Since this merge happens with no allowlist or denylist, and later merges in `TaskCommands#env`/`Command#unbundled_env` do not strip or block it for keys outside the fixed hardcoded set, an attacker who can apply a label to their own tracked PR (e.g. `SSH_AUTH_SOCK`) can inject that variable name into the environment reaching `PTY.spawn`.

### Finding Description
The claimed binding is: the set of env var **names** reaching `PTY.spawn` in `Command#start` == `BASE_ENV` keys ∪ `{'PATH'}` ∪ `Shipit.env` keys ∪ `deploy_spec.machine_env` keys ∪ `@task.env` keys, with **no** contribution from `pull_request.labels`.

Tracing the code shows this binding is false:

- `Shipit::ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`) does: [1](#0-0) 
  This merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` on top of `super` (Stack#env), unconditionally, for any label name.

- `TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`) merges, in order: `super` (base_env: `Shipit.env` + GitHub token/domain), then `@stack.env` (which for a `ReviewStack` includes the attacker-controlled label keys), then a fixed hardcoded hash (`SHIPIT_USER`, `EMAIL`, `BUNDLE_PATH`, `SHIPIT_LINK`, `TASK_ID`, `IGNORED_SAFETIES`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`), then `deploy_spec.machine_env`, then `@task.env`. [2](#0-1) 
  Only keys that collide with this fixed hardcoded list, `machine_env`, or `@task.env` get overwritten; any other label name (like `SSH_AUTH_SOCK`) survives untouched into the returned env hash.

- `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) then does `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)`, merging the task's env (containing the label-derived key) **last**, so it overrides anything in `BASE_ENV`/`PATH` with the same name. [3](#0-2) 

- `Command#start` passes this merged hash straight to `PTY.spawn`: [4](#0-3) 

- The label itself originates from `LabelCapturingHandler#capture_labels`, which is triggered by ordinary, legitimately-signed GitHub `pull_request` webhook events (`labeled`/`opened`/`reopened`/`unlabeled`) for a repo that already has a Shipit review stack configured, and simply persists `pull_request.labels` from the payload with no filtering: [5](#0-4) 

No existing guard (`verify_signature`, `ExplicitParameters` schema, model validations) restricts label *names*; the `ExplicitParameters` schema only requires `name: String` with no character/allowlist restriction. `EnvironmentVariables#permit`, `Shipit.env`, and `deploy_spec.machine_env` are operator-approved allowlists elsewhere in the system, but `ReviewStack#env` bypasses that model entirely by treating any label as a trusted env var name/value pair.

The attacker's exact action: open a PR against a repository that has Shipit review stacks enabled, and apply (or have applied via any actor with label permission, including themselves if the repo permits) a label literally named `SSH_AUTH_SOCK` (case-insensitive, since it's upcased). No Shipit credentials, session, or API token are required — only the ability to get that label onto the tracked PR, which GitHub delivers via a normally-signed webhook.

### Impact Explanation
This lets an unauthenticated-to-Shipit GitHub actor inject an arbitrary environment variable **name** (any label text) into the process environment for every deploy/step command run against that review stack, including custom `deploy_spec` steps and git commands that shell out via `Command`/`PTY.spawn`. For the specific case in the question, setting `SSH_AUTH_SOCK=true` mainly causes ssh-agent forwarding to fail (availability impact) unless there is a shared, predictable, and writable socket path literally named `true` on the deploy host — a host-specific and unlikely precondition, which the question itself flags as conditional. More broadly, because the merge is generic and not confined to `SSH_AUTH_SOCK`, the same primitive lets an attacker inject other high-impact variable names not covered by the hardcoded/machine_env/task.env override list (e.g. tool-specific variables interpreted by git, ssh, bundler, or a custom deploy step), expanding the blast radius beyond simple availability loss for that one variable. This affects only the review stack tied to the attacker's own repository/PR — it does not cross-contaminate other stacks or tenants, and does not directly expose `GITHUB_TOKEN` or other Shipit secrets. Given the demonstrated but conditional nature of the concrete `SSH_AUTH_SOCK` exploit path, this is best categorized as a boundary/allowlist violation with limited direct proven impact under the stated constraints, though the underlying primitive (unfiltered label-to-env-var injection) is a real and reachable defect in `ReviewStack#env`.

### Likelihood Explanation
Preconditions: the target repository must have Shipit review stacks configured, an open PR tracked by a non-archived `ReviewStack`, and a deploy/task step that shells out (any deploy triggers `TaskCommands#env`/`Command`). Applying a label named `SSH_AUTH_SOCK` requires only label-write permission on the PR (commonly available to maintainers, and in some repo configurations to the PR author or collaborators) and requires no Shipit secret, session, or API token — GitHub delivers the event as an ordinary, correctly-signed webhook. The cost is trivial (one label add) and repeatable on every relabel event for that PR/repo.

### Recommendation
Do not let arbitrary label text become an environment variable name reaching `Command`/`PTY.spawn`. `ReviewStack#env` should either (a) drop this label→env merge entirely, or (b) restrict it to a small, fixed, explicitly namespaced prefix (e.g. only labels matching `SHIPIT_LABEL_*` or similar) and/or filter out any label name that collides with security-sensitive variables (`SSH_AUTH_SOCK`, `PATH`, `LD_PRELOAD`, `GIT_SSH_COMMAND`, `BUNDLE_*`, etc.), consistent with the `VariableDefinition`/`Shipit.env`/`deploy_spec.machine_env` operator-approval model used elsewhere.

### Proof of Concept
Minitest plan (`test/models/shipit/review_stack_test.rb` or `test/lib/shipit/task_commands_test.rb`):
1. Create a `ReviewStack` with an associated `PullRequest` whose `labels` include `"SSH_AUTH_SOCK"`.
2. Assert `stack.env["SSH_AUTH_SOCK"] == "true"` while `Shipit.env`, `deploy_spec.machine_env`, and `task.env` are all empty/do not define that key — proving the source is purely `pull_request.labels`.
3. Build a `Shipit::Task` (or `Deploy`) on this stack, instantiate `TaskCommands.new(task)`, and assert `task_commands.env["SSH_AUTH_SOCK"] == "true"`.
4. Construct a `Command` with `env: task_commands.env` and assert `command.unbundled_env["SSH_AUTH_SOCK"] == "true"`, independent of `Command::BASE_ENV`, confirming the label-sourced key reaches the hash passed to `PTY.spawn` in `Command#start`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```
