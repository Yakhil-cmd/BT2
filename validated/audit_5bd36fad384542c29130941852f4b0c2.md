### Title
Unrestricted `machine.environment` in fork `shipit.yml` allows env-var injection (e.g. `PYTHONSTARTUP`) into `deploy.override` process env - (File: app/models/shipit/deploy_spec.rb, lib/shipit/task_commands.rb, lib/shipit/command.rb)

### Summary
`DeploySpec#machine_env` returns the `machine.environment` hash from the branch's `shipit.yml` completely unfiltered, and `TaskCommands#env` merges it into the environment used for every task step, including `deploy.override`. `Command#unbundled_env` then merges this attacker-controlled hash on top of `BASE_ENV` (derived from `Bundler.unbundled_env`/`ENV`) and passes the result directly to `PTY.spawn`, so any key the fork author names in `machine.environment` — including sensitive interpreter-level variables such as `PYTHONSTARTUP` — reaches the spawned deploy process and overrides the host's own environment for that key.

### Finding Description
The broken binding: the environment reaching `PTY.spawn` for a review stack's `deploy.override` command should equal `Command::BASE_ENV` plus only host/operator-controlled keys, but in practice it equals `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` where `@env` includes `deploy_spec.machine_env`, which is `config('machine', 'environment')` read verbatim from the fork branch's `shipit.yml` [1](#0-0) .

Path:
1. `TaskCommands#env` builds the env hash for every step (`install_dependencies`, `perform`, which runs `deploy.override` steps) by merging `super`, stack env, several fixed keys, then `.merge(deploy_spec.machine_env)` and finally `.merge(@task.env)` [2](#0-1) .
2. `deploy_spec.machine_env` is sourced from `DeploySpec::FileSystem` reading the checked-out branch's `shipit.yml`, with no allowlist/permit filter applied — contrast this with `filter_deploy_envs`/`filter_rollback_envs`, which do apply `EnvironmentVariables#permit` against a `deploy_variables` allowlist, but that filtering is only applied to `@task.env` (runtime-supplied deploy variables), not to `machine_env` [3](#0-2) .
3. Each `Command.new(command_line, env:, chdir: steps_directory)` call for a `deploy.override` step receives this hash as `@env` [4](#0-3) .
4. `Command#unbundled_env` merges `@env.stringify_keys` on top of `BASE_ENV`, so any key present in `machine.environment` overrides the corresponding `BASE_ENV`/host value [5](#0-4) .
5. `Command#start` passes this exact hash to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [6](#0-5) .

For a review stack under `provisioning_behavior = allow_all`, the branch used to check out `shipit.yml` is the fork PR branch itself, which the unprivileged attacker fully controls, so the attacker can set `machine: { environment: { PYTHONSTARTUP: "/path/evil.py" } }` and have it merged into the env for the `deploy.override` step. `ReviewStack#env` only adds PR-label-derived env vars and does not filter/restrict `machine_env` either [7](#0-6) .

No guard in the reviewed code (`ExplicitParameters`, `EnvironmentVariables#permit`, model validators) restricts what keys `machine.environment` may set; the "permit" filtering mechanism exists in the codebase but is not applied to `machine_env`, confirming the divergence.

### Impact Explanation
The env hash actually delivered to `PTY.spawn` for `deploy.override` diverges from the intended trusted baseline by including arbitrary attacker-chosen key/value pairs, up to and including interpreter-affecting variables like `PYTHONSTARTUP`, `PYTHONPATH`, `LD_PRELOAD`, `RUBYOPT`, etc., for any command in the step (not just python-named ones) that is influenced by such environment variables. This is repeatable on every deploy of the review stack and confined to the fork's own review stack/deploy host process, but since it runs on the shared Shipit deploy host, it represents host-level command/environment influence rather than an isolated sandbox — matching the "command running that should not" impact class for the deploy host.

### Likelihood Explanation
Preconditions: the target repository must have `provisioning_behavior = allow_all` (so review stacks/deploys run for unprivileged fork PRs without maintainer approval) and must use the standard `shipit.yml`-driven `machine.environment` mechanism (no bespoke `DeploySpec::FileSystem` override that strips `machine.environment`). Given those, the attacker cost is trivial: open a PR from a fork with a `shipit.yml` containing a `machine.environment` entry. No secrets, tokens, or privileged roles are required, and the action is fully repeatable across any repository configured with `allow_all`.

### Recommendation
Restrict `machine.environment` to a fixed, non-interpreter-affecting allowlist (or block known-dangerous keys such as `PYTHONSTARTUP`, `LD_PRELOAD`, `RUBYOPT`, `PYTHONPATH`, `PERL5OPT`, `BASH_ENV`, etc.), or disallow `machine.environment` entirely for repositories with `provisioning_behavior = allow_all` unless the PR has been explicitly labeled/approved by a maintainer. Apply the same `EnvironmentVariables#permit` allowlist pattern already used for `filter_deploy_envs`/`filter_rollback_envs` to `DeploySpec#machine_env`.

### Proof of Concept
minitest plan (no live GitHub):
1. In `test/models/deploy_spec_test.rb`-style test, build a `DeploySpec` from a config hash equivalent to:
```yaml
machine:
  environment:
    PYTHONSTARTUP: /tmp/evil.py
deploy:
  override:
    - python script.py
```
2. Assert `deploy_spec.machine_env == { 'PYTHONSTARTUP' => '/tmp/evil.py' }`.
3. Construct a `TaskCommands`/`Command` for a stubbed `Task` on a `ReviewStack` (fork PR, `provisioning_behavior: allow_all`) using this spec, and call `command.unbundled_env`.
4. Assert `command.unbundled_env['PYTHONSTARTUP'] == '/tmp/evil.py'`, proving the fork-controlled key reaches the hash passed to `PTY.spawn` in `Command#start` — i.e., assert equality of `command.unbundled_env.fetch('PYTHONSTARTUP')` against the attacker-supplied value, and inequality against the original `Command::BASE_ENV['PYTHONSTARTUP']` (nil/absent), demonstrating the override.

### Citations

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
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
