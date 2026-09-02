### Title
Unsanitized GitHub PR label injection into deploy subprocess environment enables `LD_PRELOAD` RCE - (File: `app/models/shipit/review_stack.rb`)

### Summary
`Shipit::ReviewStack#env` merges every label name on the associated pull request directly into the environment hash used to spawn deploy subprocesses, with no whitelist check. Since `TaskCommands#perform`/`DeployCommands#perform` pass this hash straight into `Command.new(..., env:, chdir: steps_directory)` and `Command#unbundled_env`/`PTY.spawn` without ever calling `EnvironmentVariables#permit`, an attacker-controlled label such as `LD_PRELOAD` reaches the spawned process's environment unfiltered.

### Finding Description
The broken binding: the set of keys injected into the subprocess environment via `Command#unbundled_env` should equal (be a subset of) the keys permitted by a whitelist (e.g. via `EnvironmentVariables#permit(variable_definitions)`), but in this code path it does not.

Trace:
- `Shipit::ReviewStack#env` [1](#0-0)  takes `pull_request.labels` and merges `{label_name.upcase => "true"}` directly into the hash returned by `super` (the `Stack#env`/`TaskCommands#env` chain), with **no filtering**.
- `TaskCommands#env` [2](#0-1)  merges `@stack.env` (which for a `ReviewStack` is the label-poisoned hash) along with fixed keys and `deploy_spec.machine_env`/`@task.env`, again with no call to `EnvironmentVariables.with(env).permit(...)`.
- `DeployCommands#env` [3](#0-2)  just calls `super.merge(...)`, inheriting the unfiltered hash.
- `TaskCommands#perform`/`DeployCommands#steps` build `Command.new(command_line, env:, chdir: steps_directory)` [4](#0-3)  passing this hash directly as the subprocess env.
- `Command#unbundled_env` merges `BASE_ENV`, `PATH`, and `@env.stringify_keys` unconditionally [5](#0-4) , and `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [6](#0-5) .
- The only whitelist mechanism in the codebase, `EnvironmentVariables#permit` [7](#0-6) , is never invoked anywhere in this `env` build/consume chain — it is used elsewhere only for `deploy_variables`/`filter_deploy_envs` validation of *user-supplied task trigger params* (`Stack#trigger_deploy`/`#build_deploy` filtering `env` passed by a human triggering a deploy), not for the `pull_request.labels`-derived keys that `ReviewStack#env` injects.

So an attacker who can label their own review-stack-backing PR with `LD_PRELOAD` causes that literal key/value (`"LD_PRELOAD" => "true"`) to be present in the environment of every command `PTY.spawn`'d for that stack's deploy, executed with `chdir` at the attacker's own checkout. Combined with a malicious ELF named `true` committed at the checkout root (relative path resolution by the dynamic linker under `LD_PRELOAD=true`), this yields native code execution inside the deploy subprocess tree on the shared deploy host.

No existing guard intercepts this: `verify_signature`/webhook signature checks only authenticate that the payload came from GitHub for *that* repository (they don't restrict label *content*); `LabeledHandler`/`LabelCapturingHandler` simply persist `payload.pull_request.labels` into `pull_request.labels` verbatim; `deploy_spec.machine_env` is additive (adds fixed vars), not a whitelist filter on `stack.env`; and `EnvironmentVariables#permit` is architecturally absent from the `ReviewStack#env` → `Command.new` path.

### Impact Explanation
This is Critical: arbitrary native code execution on the shared deploy host, inside the subprocess tree that runs deploy steps for that stack (and via `LD_PRELOAD` persisting in the environment for the whole process image, effectively any child process spawned during that deploy). Because `deploy_spec.deploy_steps!` and checkout are per-review-stack (per-branch/per-PR), and review stacks all execute on the same deploy worker infrastructure as regular stacks, this can expose deploy-time secrets (`GITHUB_TOKEN`, other injected credentials) and potentially pivot to other stacks' deploy processes/data on the same host. It's repeatable for any repository with `review_stacks_enabled` and capistrano/other non-empty `deploy_steps!`, as many times as the attacker wants to relabel/redeploy.

### Likelihood Explanation
Preconditions required: `review_stacks_enabled` for the repository, a live non-archived `Shipit::ReviewStack` for the attacker's PR, and `deploy_spec.deploy_steps!` non-empty. The main open question is whether the attacker (as defined — an unprivileged external contributor) can actually attach a label to their own PR; on stock GitHub, adding labels normally requires "triage" or higher repo permissions, not just being the PR author. This document's Rules section stipulates the attacker can label their own PR, so under that stipulated threat model the likelihood is high and the attacker cost is low (no secrets needed, just a GitHub label and a git push). If that stipulation doesn't hold in the real deployment (label-adding requires write access), the practical likelihood is much lower and shifts the finding toward "requires a semi-privileged collaborator," which would need separate confirmation outside this codebase.

### Recommendation
In `Shipit::ReviewStack#env`, do not merge raw `pull_request.labels` names as environment variable keys at all, or at minimum pass the merged result through `EnvironmentVariables.with(env).permit(deploy_spec.machine_env_variable_definitions)` (or an explicit dedicated whitelist for review-stack label flags) before it is returned up the `env` chain. Additionally, harden `Command#unbundled_env`/`Command.new` to reject or strip dangerous dynamic-linker/interpreter-influencing variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, etc.) unconditionally regardless of source.

### Proof of Concept
Add to `test/unit/deploy_commands_test.rb` (or a new test file) a minitest that:
1. Builds a `Shipit::ReviewStack` with an associated `pull_request` whose `labels` includes `"LD_PRELOAD"`.
2. Builds/loads a `Deploy` task for that stack with `deploy_spec.deploy_steps!` non-empty.
3. Asserts:
```ruby
env = DeployCommands.new(deploy).env
assert env.key?('LD_PRELOAD'), "expected unsanitized label to leak into subprocess env"
assert_raises(Shipit::EnvironmentVariables::NotPermitted) do
  Shipit::EnvironmentVariables.with(env).permit(deploy_spec.machine_env_variable_definitions || [])
end
```
This demonstrates that `DeployCommands#env` contains an unwhitelisted `LD_PRELOAD` key sourced purely from `stack.pull_request.labels`, with no `EnvironmentVariables#permit` call anywhere between label capture and `Command.new`.

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

**File:** lib/shipit/task_commands.rb (L23-27)
```ruby
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

**File:** lib/shipit/deploy_commands.rb (L9-16)
```ruby
    def env
      commit = @task.until_commit
      super.merge(
        'SHA' => commit.sha,
        'REVISION' => commit.sha,
        'DIFF_LINK' => diff_url
      )
    end
```

**File:** lib/shipit/command.rb (L92-92)
```ruby
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
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
