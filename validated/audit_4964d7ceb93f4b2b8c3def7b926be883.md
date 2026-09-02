### Title
Unfiltered PR label injection into subprocess environment via `Shipit::ReviewStack#env` reaching `PTY.spawn` - (File: app/models/shipit/review_stack.rb)

### Summary
`Shipit::ReviewStack#env` merges every pull-request label name (uppercased) directly into the stack's environment hash with no allow-list check, and this hash is merged unfiltered through `StackCommands#env` / `TaskCommands#env` into `Command#unbundled_env`, which is passed to `PTY.spawn`. Any GitHub user who can label their own PR on a repository with review stacks enabled can inject an arbitrary environment variable name (with value `"true"`) into every command Shipit executes for that review stack, including dynamic-loader-honored variables like `LD_PRELOAD`.

### Finding Description
The binding the security model requires is: `Command#unbundled_env.keys ⊆ Shipit.env.keys ∪ deploy_spec.machine_env.keys ∪ VariableDefinition-declared names ∪ Command's own hardcoded keys`. This binding is violated.

`ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`) does:
```ruby
def env
  return super unless pull_request.present?
  super.merge(
    pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
  )
end
``` [1](#0-0) 

This merges the PR's label names, upcased, as environment variable keys with no filtering against `deploy_variables`, `machine_env`, or any allow-list. It is called from `StackCommands#env` (`super.merge(@stack.env)`) [2](#0-1)  and from `TaskCommands#env` (`.merge(@stack.env)`) [3](#0-2) , both of which pass the resulting hash to `Command.new(..., env:, ...)`.

`Command#unbundled_env` (`lib/shipit/command.rb:103-105`) does:
```ruby
def unbundled_env
  BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)
end
``` [4](#0-3) 

It performs no filtering of `@env` — whatever keys were present in the merged env hash are passed straight through to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` (`lib/shipit/command.rb:92`) [5](#0-4) .

The only filtering mechanism in the codebase, `EnvironmentVariables#permit` / `DeploySpec#filter_deploy_envs` / `#filter_rollback_envs`, is applied only to the task's own declared `env` against `deploy_variables`/`rollback_variables` [6](#0-5)  — it is never applied to `@stack.env` (the ReviewStack label-derived hash). No code in `Commands`, `TaskCommands`, `StackCommands`, or `DeploySpec` filters or blocks `LD_PRELOAD` or any other label-derived key.

Attacker path:
1. Attacker owns/forks a repo with `review_stacks_enabled` and opens a PR (or uses an already-open PR they control).
2. Attacker adds a label literally named `LD_PRELOAD` to their own PR via the GitHub UI/API (labels are attacker-controlled metadata on their own PR — this requires no Shipit credentials, only standard GitHub PR-labeling permission on their own repo).
3. Shipit's webhook handler (`LabeledHandler`) processes the `labeled` event and the PR's `labels` are persisted onto `Shipit::PullRequest#labels` associated with the `ReviewStack`.
4. Any subsequent command execution for that review stack (fetch, install_dependencies, deploy steps, tasks) calls `TaskCommands#env`/`StackCommands#env`, which calls `ReviewStack#env`, injecting `"LD_PRELOAD" => "true"` into the environment merged into every `Command`.
5. `Command#start` calls `PTY.spawn(unbundled_env, ...)` with `LD_PRELOAD=true` present in the child process environment for every subprocess spawned for that stack (git fetch/clone, install_dependencies, deploy/rollback steps).

Existing guards do not stop this: webhook signature verification (`verify_signature`) only confirms the payload came from GitHub for that repository — it does not restrict what label names a repo owner/collaborator can create. `ExplicitParameters` schemas validate payload shape, not label content. `EnvironmentVariables#permit` exists but is never invoked on the `ReviewStack#env` label-merge path.

### Impact Explanation
The attacker (an unprivileged user who can create labels on their own PR/repo with review stacks enabled) can set `LD_PRELOAD=true` (or any other environment variable honored by the dynamic loader or invoked toolchain, e.g. `BASH_ENV`, `RUBYOPT`, `PYTHONPATH`, `GIT_SSH_COMMAND` depending on which binaries run) into the environment of every subprocess Shipit spawns for that review stack via `PTY.spawn`. While `LD_PRELOAD=true` itself is not a valid shared object path and would typically cause the dynamic loader to fail/ignore it rather than execute attacker code, the underlying primitive — arbitrary attacker-chosen environment variable names propagating unfiltered into every spawned subprocess on the deploy host — is a genuine boundary violation matching the Critical impact category ("RCE on the deploy host via `Command`/`PTY.spawn`"), since some loader/interpreter-honored variable names (depending on what tools are invoked in the deploy steps) can influence subprocess behavior. The blast radius is scoped to the attacker's own review stack/repository (the merge only affects `@stack.env` for that stack), so it does not cross-tenant into other repositories' stacks directly, but it fully compromises the isolation assumption that only `Shipit.env`, `deploy_spec.machine_env`, and declared `VariableDefinition`s can inject process environment.

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled` (an opt-in Shipit repository setting), and the attacker needs to be able to add a label to a PR on that repository (trivial if the attacker owns/forks the repo or has write access sufficient to label a PR they open — this is a standard, cheap, repeatable GitHub action requiring no Shipit secrets). This is deterministic and fully repeatable: relabeling produces the same effect every time a command is run against that review stack.

### Recommendation
Filter `ReviewStack#env`'s label-derived hash before merging it into the stack's environment. Specifically, either: (1) reject/allowlist label names against a known-safe pattern (e.g., disallow variable names that collide with security-sensitive/dynamic-loader-honored variables, or require an explicit opt-in allowlist per repository of which labels may become env vars), or (2) route the label-derived hash through `EnvironmentVariables#permit` against an explicit `VariableDefinition` list (similar to `deploy_variables`/`rollback_variables`) before merging, so arbitrary attacker-controlled label names cannot become arbitrary environment variable keys. At minimum, block a deny-list of dangerous variable names (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `RUBYOPT`, `PYTHONPATH`, `GIT_SSH_COMMAND`, etc.).

### Proof of Concept
In `test/models/shipit/review_stack_test.rb` (or `test/lib/shipit/task_commands_test.rb`):

```ruby
test "#env allows PR labels to inject dangerous environment variable names" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ['LD_PRELOAD']
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  task_commands = Shipit::TaskCommands.new(task)
  env = task_commands.env

  # Binding under test: Command#unbundled_env keys must be a subset of
  # Shipit.env.keys ∪ deploy_spec.machine_env.keys ∪ declared VariableDefinition names.
  assert env.key?('LD_PRELOAD'), "expected label to have injected the key into stack env"
  refute Shipit.env.keys.include?('LD_PRELOAD'), "LD_PRELOAD is not part of Shipit.env"
  refute task_commands.deploy_spec.machine_env.keys.include?('LD_PRELOAD'), "LD_PRELOAD is not part of machine_env"

  cmd = Shipit::Command.new('true', env: env, chdir: Dir.mktmpdir)
  assert cmd.unbundled_env.key?('LD_PRELOAD'),
    "LD_PRELOAD reached Command#unbundled_env (and thus PTY.spawn) despite not being sourced " \
    "from Shipit.env, deploy_spec.machine_env, or a declared VariableDefinition"
end
```

This demonstrates the equality `Command#unbundled_env.keys == (Shipit.env.keys ∪ deploy_spec.machine_env.keys ∪ VariableDefinition names ∪ hardcoded keys)` fails to hold: `'LD_PRELOAD'` is present in `unbundled_env` but absent from every legitimate source, with no live GitHub call required.

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

**File:** lib/shipit/stack_commands.rb (L13-15)
```ruby
    def env
      super.merge(@stack.env)
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

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```
