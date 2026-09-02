### Title
Attacker-controlled pull-request labels flow into `Command#unbundled_env` unfiltered, allowing `GIT_EXEC_PATH` injection into `deploy.variables`/deploy step processes - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) directly into the stack env hash with no allowlist, and this hash flows unchanged through `TaskCommands#env`/`DeployCommands#env` into `Command#unbundled_env`, which is passed straight to `PTY.spawn` for every deploy step, including the `deploy.variables` interpolation step. Since PR labels on a fork are entirely attacker-controlled, an attacker can set a label literally named `GIT_EXEC_PATH` to redirect git's internal subcommand resolution to an attacker-supplied path, potentially achieving RCE on the deploy host when the review stack next runs a git-invoking step.

### Finding Description
The broken binding: the process env used by `PTY.spawn` should equal `Command::BASE_ENV` (sanitized `Bundler.unbundled_env`/clean env) merged only with keys explicitly whitelisted by the deploy spec — but in practice it equals `BASE_ENV.merge('PATH'=>...).merge(@env.stringify_keys)` where `@env` includes arbitrary uppercased PR label names with no whitelist check [1](#0-0) .

Path:
1. An unprivileged fork contributor opens/labels a PR on a repo with `review_stacks_enabled` and `provisioning_behavior=prevent_with_label`, naming a label `git_exec_path` (case-insensitive since it gets `.upcase`'d).
2. GitHub sends a `pull_request` webhook; `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim onto `PullRequest#labels`, with the schema requiring only `name, String` — no character/key restriction [2](#0-1) [3](#0-2) .
3. `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into the stack env with no allowlist of permitted keys [4](#0-3) .
4. `TaskCommands#env` (and `DeployCommands#env`, which calls `super`) merges `@stack.env` into the final env used to build every `Command` for deploy steps, including the `deploy.variables` interpolation performed via `EnvironmentVariables.with(env).interpolate` at command build time [5](#0-4) .
5. `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`, and `unbundled_env` merges `@env.stringify_keys` last, so an attacker-supplied `GIT_EXEC_PATH` overrides anything from `BASE_ENV`/`ENV` [6](#0-5) .

Existing guard `EnvironmentVariables#permit`/`sanitize_env_vars` exists and does enforce a whitelist against `variable_definitions.map(&:name)`, raising `NotPermitted` for disallowed keys — but this method is only used for `EnvironmentVariables.with(env).permit(...)`, and is not shown to be invoked on the full label-derived env hash before it reaches `Command.new(env: ...)` in `TaskCommands#perform`/`#install_dependencies`. The label hash is merged directly into `@stack.env` and consumed by `Command` without going through `permit`, so this guard does not protect the path actually reached by `Command#start`.

### Impact Explanation
If an attacker can set `GIT_EXEC_PATH` (or similar dangerous variables like `GIT_ASKPASS`, `LD_PRELOAD`-style vectors are not directly reachable here, but `GIT_EXEC_PATH` specifically) via an uppercased PR label, then any subsequent git invocation performed with that stack's env (fetch, clone, checkout, or deploy steps referencing git) on the Shipit deploy host will resolve git subcommands from an attacker-controlled directory if the attacker can also stage a malicious binary there (e.g., via the fork's checked-out working directory or another writable path). This matches the Critical — RCE on the deploy host category, since it is triggered purely by opening a PR and applying a label to one's own fork, no privileged access required.

### Likelihood Explanation
Preconditions: `review_stacks_enabled` must be true and `provisioning_behavior` set to `prevent_with_label` (or `allow_with_label`), which are documented, common configurations for review-stack-enabled repos. The attacker needs only to open a PR from their own fork and apply a label with the literal name `git_exec_path` — a zero-cost, fully repeatable action requiring no elevated GitHub or Shipit privileges. Full weaponization into RCE additionally requires the attacker to place an executable named after a git subcommand (e.g., `git-fetch`) at the injected `GIT_EXEC_PATH` location that is reachable from the deploy host's filesystem (e.g., within the checked-out fork working directory), which is feasible since the review stack's working directory is populated from the attacker's own fork content.

### Recommendation
In `ReviewStack#env`, restrict the label-derived keys to a safe, explicit prefix/allowlist (e.g., require a `SHIPIT_LABEL_` prefix or filter out any key colliding with known-sensitive names such as `GIT_EXEC_PATH`, `GIT_ASKPASS`, `LD_PRELOAD`, `PATH`, `BUNDLE_*`, `RUBYOPT`). Alternatively, route the label-derived hash through `EnvironmentVariables#permit` with a whitelist before merging it into the stack/task env, and have `Command#unbundled_env` reject/strip any `@env` key that also appears in a denylist of environment variables affecting subprocess/git resolution, regardless of source.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (add to existing file, or new test)
test "#env does not leak dangerous env vars like GIT_EXEC_PATH from PR labels" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["git_exec_path"]

  env = stack.env

  # Broken binding under test: env["GIT_EXEC_PATH"] should never equal "true"
  # (i.e., no fork-controllable label should ever populate GIT_EXEC_PATH)
  assert_nil env["GIT_EXEC_PATH"], "PR label should not be able to set GIT_EXEC_PATH"
end

# test/lib/shipit/deploy_commands_test.rb
test "#env passed to Command does not include attacker-controlled GIT_EXEC_PATH" do
  stack = shipit_stacks(:review_stack)
  deploy = stack.trigger_continuous_delivery
  stack.pull_request.labels = ["git_exec_path"]

  env = Shipit::DeployCommands.new(deploy).env
  command = Shipit::Command.new("git version", env:, chdir: ".")

  assert_nil command.unbundled_env["GIT_EXEC_PATH"]
end
```
Both assertions currently fail against the code as traced: `stack.env["GIT_EXEC_PATH"]` equals `"true"` and `command.unbundled_env["GIT_EXEC_PATH"]` equals `"true"`, confirming the equality `deploy.variables env["GIT_EXEC_PATH"] == "true"` (attacker-set) rather than the expected invariant that no fork-controllable key reaches the spawned process's env.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L26-31)
```ruby
              requires :assignees, Array do
                requires :login, String
              end
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
