### Title
Unfiltered `shipit.yml` `machine.environment` allows arbitrary env-var injection (including `BUNDLE_PATH`) into the spawned deploy process - ([File: app/models/shipit/deploy_spec.rb], [File: lib/shipit/task_commands.rb], [File: lib/shipit/command.rb])

### Summary
`DeploySpec#machine_env` returns the `machine.environment` section of the checked-out `shipit.yml` completely unfiltered, and `TaskCommands#env` merges it into the process environment *after* Shipit's own hard-coded defaults (including `BUNDLE_PATH`). For a `ReviewStack`, `shipit.yml` is read from the exact commit under review, so once a maintainer labels a PR under `provisioning_behavior=allow_with_label`, the PR author's own file content controls arbitrary environment keys/values that reach `PTY.spawn` in `Command#start`.

### Finding Description
The broken binding: the environment hash passed to `PTY.spawn` for a review-stack task should equal `{trusted_keys_only}`, but in practice it equals `hardcoded_defaults.merge(attacker_controlled_machine_env).merge(task.env)`, i.e. attacker input is not excluded.

Trace:
- `DeploySpec#machine_env` (app/models/shipit/deploy_spec.rb:69-71) is `config('machine', 'environment') || {}` — a raw pass-through of parsed YAML with no allow-list, no `EnvironmentVariables#permit` call (that filtering is only applied to `deploy_variables`/`rollback_variables` via `filter_deploy_envs`/`filter_rollback_envs`, not to `machine_env`). [1](#0-0) 
- `DeploySpec::FileSystem` loads this config from whatever `shipit.yml`/`.shipit/shipit.yml` exists in the checked-out working tree at the task's commit (`config_file_path`/`load_config`), i.e. the content of the PR branch being reviewed. [2](#0-1) 
- `TaskCommands#env` builds the final task environment: `super.merge(@stack.env).merge({... 'BUNDLE_PATH' => Rails.root.join('data','bundler').to_s ...}).merge(deploy_spec.machine_env).merge(@task.env)`. Because `deploy_spec.machine_env` is merged **after** the hard-coded `BUNDLE_PATH` default, a `machine.environment.BUNDLE_PATH` key in the attacker's `shipit.yml` silently overrides Shipit's intended value (and any other key can be injected the same way). [3](#0-2) 
- `Command#unbundled_env` merges `@env.stringify_keys` unfiltered on top of `BASE_ENV`/`PATH`, with no denylist/allowlist of dangerous keys (`BUNDLE_PATH`, `RUBYOPT`, `GEM_HOME`, `GIT_SSH_COMMAND`, etc.). [4](#0-3) 
- `Command#start` passes this exact hash straight to `PTY.spawn`. [5](#0-4) 

Provisioning reachability: for `provisioning_behavior_allow_with_label`, a `labeled`/`opened`/`reopened` webhook creates or unarchives the `ReviewStack` once the provisioning label is present on the PR. [6](#0-5) 
Note: for a fork PR, applying the label is a maintainer action (label-add generally requires triage/write permission on GitHub), not something the unprivileged author can self-trigger — that part of the question's premise ("self-added label") is not accurate. However, this doesn't block the finding: the label is a routine, low-trust "let's preview this" action; the exploit content (`machine.environment` in `shipit.yml`) is entirely authored by the unprivileged fork PR author and is not re-reviewed at label time.

Separately, `ReviewStack#env` (app/models/shipit/review_stack.rb:84-93) does turn PR label *names* into env vars (`labels[label_name.upcase] = "true"`), but this is merged into `@stack.env` *before* the hard-coded `BUNDLE_PATH` default in `TaskCommands#env`, so a label literally named `BUNDLE_PATH` would be overwritten — that specific sub-vector does not survive. The `shipit.yml`-based vector does survive because it is merged last (aside from `@task.env`). [7](#0-6) 

Existing guards checked and found not applicable: `EnvironmentVariables#permit` is only invoked by `filter_deploy_envs`/`filter_rollback_envs`, not by `machine_env`; no model validation restricts `machine.environment` keys; `Command#env` only calls `.to_s` on values, performing no filtering.

### Impact Explanation
Once a review stack is labeled/provisioned, the environment merged in for every task/deploy of that stack — set from attacker-authored `shipit.yml` — reaches the spawned deploy process unfiltered. This is not limited to `BUNDLE_PATH`: any environment key (`RUBYOPT`, `GEM_HOME`, `GEM_PATH`, `GIT_SSH_COMMAND`, `LD_PRELOAD`-style interpreter hooks, etc.) that influences subsequent `bundle install`/`bundle exec`/git/ruby invocations on the deploy host can be injected. This matches the Critical RCE-on-deploy-host category via `Command`/`PTY.spawn`. Blast radius is scoped to the stack/repository whose review stack was provisioned, but repeatable on every push/label event for that stack, and on any other repository configured with `allow_with_label` review stacks.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled with `provisioning_behavior=allow_with_label` (or `allow_all`, where no label gate exists at all). A maintainer/triager must add the provisioning label to the PR (a routine, low-scrutiny action for enabling app previews) — this is the only privileged step; the malicious `shipit.yml` content itself requires no privilege beyond opening the PR. Attacker cost is low (a normal PR); feasibility depends on the target actually merging/checking out the fork's commit, which is standard for review-app style git flows using PR head SHAs. Not directly self-triggerable end-to-end by the attacker alone under `allow_with_label`, which lowers the likelihood versus `allow_all`.

### Recommendation
Do not trust `machine.environment` from an untrusted checkout unfiltered. Apply the same allow-list mechanism used for `deploy_variables`/`rollback_variables` (`EnvironmentVariables#permit`) to `machine_env`, restrict it to a repository-configured allow-list of variable names, and ensure Shipit's own reserved keys (`BUNDLE_PATH`, `PATH`, `GEM_HOME`, etc.) are applied last/cannot be overridden by repo-supplied config, especially for `ReviewStack` tasks originating from forks.

### Proof of Concept
Minitest plan (`test/lib/shipit/task_commands_test.rb` or similar, no live GitHub required):
1. Build a `ReviewStack` (or stub a `Stack`) with `provisioning_behavior: :allow_with_label` and a fixture `shipit.yml` containing:
   ```yaml
   machine:
     environment:
       BUNDLE_PATH: "/tmp/attacker-gems"
   ```
2. Instantiate `TaskCommands.new(task)` where `task.stack` is the above stack and `task.working_directory` points at the fixture checkout.
3. Assert: `task_commands.env['BUNDLE_PATH']` equals `"/tmp/attacker-gems"`, not `Rails.root.join('data','bundler').to_s`, demonstrating that `deploy_spec.machine_env` overrides the intended default.
4. Assert further: `Command.new('true', env: task_commands.env, chdir: task.working_directory).unbundled_env['BUNDLE_PATH'] == "/tmp/attacker-gems"`, showing the value reaches the hash passed to `PTY.spawn`.

Both sides of the intended equality (`env['BUNDLE_PATH'] == Rails.root.join('data','bundler').to_s`) diverge after tracing the merge order in `TaskCommands#env`, confirming the vulnerability.

### Citations

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
    end
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L98-107)
```ruby
      def load_config
        return if config_file_path.nil?

        if !Shipit.respect_bare_shipit_file? && config_file_path.to_s.end_with?(*bare_shipit_filenames)
          return { 'deploy' => { 'pre' => [shipit_not_obeying_bare_file_echo_command, 'exit 1'] } }
        end

        config_obj = read_config(config_file_path)
        build_config(config_file_path, config_obj)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L85-97)
```ruby
          def archive?
            (repository.provisioning_behavior_allow_with_label? && !pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && pull_request_has_provisioning_label?)
          end

          def unarchive?
            (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
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
