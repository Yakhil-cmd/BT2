### Title
Unprivileged PR labels inject arbitrary-named, unfiltered environment variables (including `IFS`) into the `ReviewStack` deploy environment - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) as an environment-variable **key** into the stack's environment hash with no allowlist, and that hash flows unfiltered through `TaskCommands#env` into `Command#unbundled_env` and finally into `PTY.spawn`'s environment. This lets a PR author (per the threat model, someone who can label their own PR) set the name of any environment variable — including `IFS` — that reaches the spawned deploy process, something the `EnvironmentVariables#permit` allowlist mechanism is supposed to prevent for stack/task-supplied env.

### Finding Description
The broken binding: the set of environment variable keys that reach `PTY.spawn` for a `deploy.variables`/deploy step should equal the whitelist enforced by `EnvironmentVariables#permit` (`filter_deploy_envs`/`filter_task_envs`), i.e. `spawned_env.keys ⊆ deploy_spec.deploy_variables.map(&:name)`. In practice it does not:

- `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase] = "true" }` directly on top of `Stack#env`, with no key filtering: [1](#0-0) 
- Labels are persisted verbatim from the webhook payload with no character/format sanitization: [2](#0-1) 
- `TaskCommands#env` merges `@stack.env` (which includes the label-derived keys) together with other env sources and passes it straight into `Command.new`: [3](#0-2) [4](#0-3) 
- `Command#unbundled_env` merges this env, including any label-derived `IFS` key, into `BASE_ENV`, and that merged hash is passed to `PTY.spawn` as the environment of the spawned process: [5](#0-4) 
- The allowlist mechanism `EnvironmentVariables#permit` exists and is used elsewhere (e.g., `filter_deploy_envs`/`filter_task_envs` on `@task.env`), but is never applied to `Stack#env`/`ReviewStack#env` before it reaches `Command`: [6](#0-5) 

So the invariant "the deploy step inherits no fork-controllable key such as `IFS`" is indeed broken: an attacker who can label their PR "ifs" causes `IFS=true` to appear in the spawned process's environment.

**Important caveat that weakens the "attacker-chosen argv" claim:** the injected value is always the hardcoded literal string `"true"` — `labels[label_name.upcase] = "true"` — not an attacker-chosen string. The attacker controls the **variable name** only, not its value. Setting `IFS="true"` makes the characters `t`,`r`,`u`,`e` act as field separators (not a chosen delimiter such as a space or comma), and this only affects `argv` construction if the specific deploy step in `shipit.yml` is executed through a real shell (`/bin/sh -c`) with unquoted variable expansions. `Command#parse_arguments`/`PTY.spawn(env, *args, ...)` execute pre-split argv arrays; Ruby only routes a command through `/bin/sh` when the underlying string contains shell metacharacters, which is determined by the *repository's own* `shipit.yml` step content, not by anything the fork attacker controls. Consequently, deterministic "attacker-chosen argv" RCE is not demonstrated by the engine alone — it depends on repository-specific deploy scripts performing unquoted shell-variable expansion.

### Impact Explanation
Confirmed impact: an unfiltered, attacker-influenceable environment-variable **name** (with fixed value `"true"`) reaches the `Command`/`PTY.spawn` environment of the review-stack's `deploy` steps, bypassing the `EnvironmentVariables#permit` allowlist that is supposed to police env injected into deploy processes. This can shadow operationally significant variables (`PATH`, `BUNDLE_GEMFILE`, `RUBYOPT`, `GIT_SSH_COMMAND`, `HOME`, `IFS`, etc.) with the literal string `"true"`, potentially breaking or subtly corrupting deploy tooling behavior for that stack. This is a genuine, reproducible defect confined to `ReviewStack`s of repositories using `allow_with_label`/PR-based provisioning. It does **not**, however, constitute demonstrated Critical RCE with fully attacker-chosen argv, because the value is fixed and shell-splitting behavior depends on the target repository's own deploy step syntax, not on anything guaranteed by this engine. The realistic classification is env-integrity violation for a single stack/repository (not cross-tenant), not a proven RCE primitive.

### Likelihood Explanation
Preconditions: `provisioning_behavior=allow_with_label`, a real PR opened from a fork of a repository configured this way, and (per the stated but atypical threat model) the ability for the PR author to add labels to their own PR. Reaching the vulnerable code requires no privileged Shipit credentials — it's driven entirely by GitHub webhook data already trusted by `LabelCapturingHandler`. However, actually converting the `IFS=true` env-name injection into arbitrary command execution additionally requires the target repository's `shipit.yml` deploy steps to invoke a real shell with unquoted variable expansions containing the letters `t/r/u/e` — a repository-specific condition not guaranteed to exist.

### Recommendation
Apply an explicit allowlist to `ReviewStack#env`/`Stack#env` label merging, e.g. only allow labels matching a safe prefix (such as `SHIPIT_LABEL_*`) or run the merged hash through `EnvironmentVariables#permit` against `deploy_spec.deploy_variables` (or a dedicated review-stack label allowlist) before it is merged into `TaskCommands#env`. Additionally, explicitly strip/reject reserved/dangerous variable names (`IFS`, `PATH`, `LD_PRELOAD`, `BUNDLE_GEMFILE`, `RUBYOPT`, etc.) regardless of source.

### Proof of Concept
```ruby
# test/unit/review_stack_env_test.rb (illustrative)
test "PR label names inject unfiltered env keys such as IFS into deploy commands" do
  stack = shipit_stacks(:review_stack) # or build a ReviewStack fixture
  pull_request = stack.pull_request
  pull_request.update!(labels: ["ifs"]) # attacker-controlled label text

  env = stack.env
  assert_equal "true", env["IFS"], "expected label-derived IFS key to reach stack env unfiltered"

  task_commands = Shipit::DeployCommands.new(stack.deploys.build)
  command = task_commands.perform.first rescue Shipit::Command.new("true", env: task_commands.env, chdir: Dir.tmpdir)

  assert_equal "true", command.unbundled_env["IFS"],
    "IFS from PR label reached the Command/PTY.spawn environment with no allowlist filtering"
end
```
This proves the invariant violation (`IFS` reaching the spawned process env). Full RCE via argv re-splitting would additionally require asserting against a concrete `shipit.yml` deploy step performing unquoted shell expansion, which is repository-specific and not demonstrated here.

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

**File:** lib/shipit/task_commands.rb (L17-27)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
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

**File:** lib/shipit/command.rb (L92-105)
```ruby
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```
