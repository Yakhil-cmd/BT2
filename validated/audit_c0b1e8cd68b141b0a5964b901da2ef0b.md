## Analysis

**Binding claimed broken:** `{'BASH_ENV','ENV'} ∩ pull_request.labels.map(&:upcase) = ∅` for a `ReviewStack`'s merged env to be EXECUTION_TRUST-safe. I traced this against the actual code.

### Code path

`ReviewStack#env` merges every GitHub label name (upcased) into the stack env with a fixed value `"true"`, with no allowlist or blocklist: [1](#0-0) 

That hash is folded into `TaskCommands#env`, which is used as the `env:` for every `Command.new` built from `deploy_spec.deploy_steps!`/`dependencies_steps!`: [2](#0-1) [3](#0-2) 

`DeployCommands#env` further merges on top of `super` (which already includes the label-derived keys), and none of the fixed keys it adds (`SHA`, `REVISION`, `DIFF_LINK`) collide with `BASH_ENV`/`ENV`: [4](#0-3) 

`Command#initialize` stores this hash verbatim (stringified values), and `Command#unbundled_env` merges it **last**, after `BASE_ENV` and the `PATH` override — meaning attacker-supplied keys win over any pre-existing environment variable, including `PATH`: [5](#0-4) [6](#0-5) 

That merged hash is exactly what reaches `PTY.spawn`, alongside the (possibly single-string, shell-interpreted) `interpolated_arguments` and `chdir`: [7](#0-6) 

Deploy steps (e.g. `bundle exec cap $ENVIRONMENT deploy`) come from `deploy_spec.deploy_steps!`, i.e. a plain command-line string read from the repo's `shipit.yml`, which for a `ReviewStack` is checked out from the PR's own head commit: [8](#0-7) [9](#0-8) 

Because these steps are single strings containing spaces/shell tokens, Ruby's `Process.spawn`/`PTY.spawn` routes them through `/bin/sh -c "<string>"` — the classic single-string shell-invocation behavior. This confirms `env['BASH_ENV']`/`env['ENV']` become part of the actual process environment for that shell invocation.

### Verification of both sides of the equality

- Before: intended invariant is that only Shipit-internal, non-attacker-named keys reach `PTY.spawn`.
- After: `ReviewStack#env` unconditionally injects `pull_request.labels.map(&:upcase)` as keys with no exclusion list, and no downstream code (`TaskCommands#env`, `DeployCommands#env`, `Command#unbundled_env`) filters or rejects reserved/dangerous names such as `BASH_ENV`, `ENV`, `PATH`, `IFS`, `LD_PRELOAD`, etc.
- No guard (`EnvironmentVariables#permit`, `Repository`/`Stack` validations, `verify_signature`, `require_permission!`) applies here — `EnvironmentVariables#permit`/`filter_deploy_envs` is only applied to task-triggered `env:` params (`Stack#trigger_task`/`build_deploy`), not to `ReviewStack#env`'s label-derived hash. The equality is broken: an attacker's label name deterministically becomes an environment variable name honored by the shell that executes deploy steps.

The remaining condition — whether the working directory (`chdir`) is attacker-writable — holds for review stacks, since the checkout used for deploy steps is the PR's own head commit, letting the attacker commit an executable file literally named `true` (or whatever path they choose to encode as the label value, though the value here is fixed to `"true"`) into that tree.

### Caveat

Whether `BASH_ENV`/`ENV` are actually honored depends on the deploy host's `/bin/sh` implementation (e.g. `dash` ignores `BASH_ENV`; `bash` invoked as `sh` enters POSIX mode where `BASH_ENV` is disabled and `ENV` is only honored by interactive shells) — this is host/OS-dependent and outside Shipit's code, but does not change that Shipit's own code performs the unsanitized injection into the process environment reaching `PTY.spawn`.

### Title
Unsanitized PR label names injected as arbitrary environment variable names into `PTY.spawn` env for review-stack deploys - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every pull-request label name (upcased) as an environment-variable key with value `"true"` into the stack's env, with no allowlist/blocklist. This hash flows unfiltered through `TaskCommands#env`/`DeployCommands#env` into `Command#unbundled_env`, which is passed directly to `PTY.spawn` for shell-interpreted `deploy_spec.deploy_steps!`, letting an attacker who can label their own PR inject reserved variable names such as `BASH_ENV`/`ENV` into the deploy shell's environment.

### Finding Description
The intended invariant is that no attacker-controlled string becomes a key in the environment reaching `PTY.spawn`. `ReviewStack#env` breaks this by doing `labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` [10](#0-9)  and merging it into the stack env used by every deploy `Command`. `Command#unbundled_env` merges this hash *last*, after `BASE_ENV`/`PATH`, so attacker-named keys always win [6](#0-5) . This is passed straight to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [11](#0-10) , where `interpolated_arguments` for `deploy_steps!` are shell command-line strings (e.g. `bundle exec cap $ENVIRONMENT deploy`) that get executed via `/bin/sh -c`. An attacker (per the stated model, able to label their own PR) sets a label `BASH_ENV` (or `bash_env`, case-insensitive) and commits an executable file named `true` into their fork's branch (checked out as the task's working directory / `chdir`). No existing guard (`EnvironmentVariables#permit`, model validations, signature verification) filters label-derived env keys.

### Impact Explanation
If the deploy host's shell honors `BASH_ENV`/`ENV` for the spawned `sh -c` invocation, the attacker's planted `true` file is sourced as a shell startup script inside the deploy process for that review stack, achieving Critical: RCE on the deploy host via `Command`/`PTY.spawn`. Even independent of that specific env var's shell semantics, the underlying bug — arbitrary attacker-chosen environment-variable *names* reaching the shell used for deploy commands, overriding `PATH` and other base env — is itself a serious violation of process isolation for review-stack deploys, scoped to the attacker's own review stack/fork but running with the Shipit deploy host's privileges (e.g. deploy credentials, shared filesystem).

### Likelihood Explanation
Requires: (1) review apps enabled for the repository, (2) the attacker's PR/fork being processed as a `ReviewStack`, (3) ability to label their own PR (per the stated attacker model), (4) the deploy host's `/bin/sh` implementation actually honoring `BASH_ENV`/`ENV` for non-interactive scripted invocation — this varies by OS/shell and is the main mitigating uncertainty. The label→env-key injection itself is trivially reproducible on any config with review stacks enabled.

### Recommendation
In `ReviewStack#env`, reject or namespace label-derived keys: exclude any label whose upcased name collides with reserved/dangerous environment variable names (`PATH`, `IFS`, `BASH_ENV`, `ENV`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `RUBYOPT`, `PERL5LIB`, `PYTHONSTARTUP`, `GIT_SSH`, etc.), or better, prefix all label-derived keys (e.g. `LABEL_<NAME>`) so they can never collide with process/shell-significant variable names. Additionally, ensure `Command#unbundled_env` cannot let arbitrary `@env` keys override `PATH`/other security-relevant base variables.

### Proof of Concept
Minitest plan (no live GitHub):
1. Build a `ReviewStack` fixture with an associated `pull_request` whose `labels` returns `['BASH_ENV', 'ENV']`.
2. Assert `stack.env['BASH_ENV'] == 'true'` and `stack.env['ENV'] == 'true'`.
3. Build a `TaskCommands`/`DeployCommands` instance for a `Deploy` task on that stack; assert `commands.env['BASH_ENV'] == 'true'` and `commands.env['ENV'] == 'true'`.
4. Call `deploy_spec.deploy_steps!` and construct the actual `Shipit::Command.new(step, env: commands.env, chdir: steps_directory)`; assert `command.env['BASH_ENV'] == 'true'` and that `command.unbundled_env['BASH_ENV'] == 'true'` / `command.unbundled_env['ENV'] == 'true'`, i.e. the exact hash that would be passed as the first argument to `PTY.spawn`.

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

**File:** lib/shipit/task_commands.rb (L90-98)
```ruby
    protected

    def steps_directory
      if sub_directory = deploy_spec.directory.presence
        File.join(@task.working_directory, sub_directory)
      else
        @task.working_directory
      end
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

**File:** lib/shipit/command.rb (L31-37)
```ruby
    def initialize(*args, chdir:, default_timeout: Shipit.default_inactivity_timeout, env: {})
      @args, options = parse_arguments(args)
      @timeout = parse_timeout(options['timeout'] || options[:timeout]) || default_timeout
      @env = env.transform_values { |v| v&.to_s }
      @chdir = chdir.to_s
      @timed_out = false
    end
```

**File:** lib/shipit/command.rb (L85-98)
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
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** app/models/shipit/deploy_spec.rb (L110-118)
```ruby
    def deploy_steps
      around_steps('deploy') do
        config('deploy', 'override') { discover_deploy_steps }
      end
    end

    def deploy_steps!
      deploy_steps || cant_detect!(:deploy)
    end
```
