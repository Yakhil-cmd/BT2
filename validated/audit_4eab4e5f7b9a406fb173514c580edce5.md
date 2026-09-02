### Title
Unsanitized pull request label names become process environment variables reaching `PTY.spawn`, allowing `GIT_PROXY_COMMAND` injection into review-stack deploy commands - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) into the stack's environment hash with no allowlist, unlike other environment-producing paths in the engine that call `EnvironmentVariables#permit`. That unsanitized hash flows through `TaskCommands#env` into `Command.new(..., env:)`, and `Command#unbundled_env`/`Command#start` merges it verbatim into the environment passed to `PTY.spawn`, so any label name (e.g. `git_proxy_command`) becomes a real environment variable (`GIT_PROXY_COMMAND`) visible to every git invocation the deploy/override step runs.

### Finding Description
The broken binding: the set of environment variables reaching `PTY.spawn` for a review-stack deploy should equal `Shipit.env ∪ Stack#env-permitted-variables`, but in practice it equals `Shipit.env ∪ Stack#env ∪ {LABEL.upcase => "true" for each PR label}` with no membership check.

Trace:
- `ReviewStack#env` unconditionally merges label-derived keys with no filtering: [1](#0-0) 
- Labels are populated straight from the webhook payload's `pull_request.labels[].name` field with no content restriction (only a signature check gates the webhook itself, not the label content): [2](#0-1) 
- `TaskCommands#env` merges `@stack.env` (which for a `ReviewStack` includes the label-derived keys) into the command environment used for every step, including override steps: [3](#0-2) 
- `Command#initialize` stores `@env` as-is (only stringifying values), and `Command#unbundled_env` merges it into the base OS environment with no key allowlist: [4](#0-3) 
- `Command#start` passes that merged hash directly to `PTY.spawn`: [5](#0-4) 

By contrast, the engine does have a sanitization primitive, `EnvironmentVariables#permit`, which raises `NotPermitted` for any key not in an explicit allowlist: [6](#0-5)  — but `ReviewStack#env` never calls it before merging label names, so the guard that exists elsewhere in the engine is bypassed for this specific path.

Root cause: `ReviewStack#env` treats PR label names as trusted configuration flags (e.g., for `allow_with_label` provisioning gating) without recognizing that the same uppercased strings become literal process environment variable names for every subsequent git/deploy command, including `GIT_PROXY_COMMAND`, which git honors to determine the command used to establish a proxied transport connection.

Exploit flow: an entity capable of adding a label named `git_proxy_command` (case-insensitive, becomes `GIT_PROXY_COMMAND` after `.upcase`) to the tracked pull request causes the webhook `labeled` event to update `pull_request.labels` via `LabelCapturingHandler#capture_labels`. On the next deploy/override run for that review stack, `Command#start` spawns git (e.g., clone/fetch) with `GIT_PROXY_COMMAND` set to an attacker-chosen value, and git executes that value to open the transport connection — arbitrary command execution on the deploy host.

### Impact Explanation
Arbitrary command execution on the Shipit deploy host under the identity running deploy tasks, matching the Critical/RCE class defined in the rules (RCE via `Command`/`PTY.spawn`). The blast radius is scoped to whichever review stack's PR receives the label, but since the deploy host and its filesystem/credentials (e.g. `GITHUB_TOKEN`, deploy secrets) are shared across stacks, a successful injection could be leveraged to pivot to other repositories/stacks hosted on the same worker.

### Likelihood Explanation
This requires: (1) the repository is configured with `provisioning_behavior: allow_with_label` (or any review-stack workflow that processes PR labels), (2) some actor or automation with GitHub label-edit permission applies a label literally named `git_proxy_command` (or another sensitive var name) to the tracked PR, and (3) a deploy/override command runs afterward. GitHub normally restricts adding labels to users with write/triage access, which is an external precondition not enforced by this engine — so whether a fully unprivileged fork contributor can trigger this depends on the target repo's collaborator/automation configuration (e.g., auto-labeler bots that label based on unprivileged PR diff content). Within the engine itself, there is no privilege check on label content once a valid webhook is received, and no allowlist filters which label names may become environment variables — this is the concrete, addressable defect.

### Recommendation
In `ReviewStack#env`, replace the raw merge with a filtered/prefixed injection, e.g. only expose label flags under a namespaced prefix (`SHIPIT_LABEL_<NAME>`) rather than raw uppercased label names, and/or run the merged hash through `EnvironmentVariables#permit` against an explicit allowlist before it is combined with `Stack#env`/`Command` env, matching the pattern already used by `EnvironmentVariables.with(env).permit(...)` elsewhere in the codebase.

### Proof of Concept
minitest outline (`test/models/shipit/review_stack_test.rb`, hypothetical addition — not present today):
```ruby
test "GIT_PROXY_COMMAND label injects into deploy env" do
  stack = shipit_stacks(:review_stack) # or build one with provisioning_behavior: allow_with_label
  pull_request = stack.pull_request
  pull_request.update!(labels: ["git_proxy_command"])

  env = stack.env
  assert_equal "true", env["GIT_PROXY_COMMAND"], "label name became a raw env var with no allowlist"

  command = Shipit::Command.new("git", "fetch", env: env, chdir: Dir.tmpdir)
  assert_equal "true", command.unbundled_env["GIT_PROXY_COMMAND"],
    "GIT_PROXY_COMMAND reaches the environment passed to PTY.spawn"
end
```
Both sides of the equality diverge: expected `env["GIT_PROXY_COMMAND"]` should be absent/unset (not attacker-controllable), but observed `env["GIT_PROXY_COMMAND"] == "true"` (attacker-controlled), confirming the vulnerability at the `ReviewStack#env` → `Command#unbundled_env` boundary.

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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```
