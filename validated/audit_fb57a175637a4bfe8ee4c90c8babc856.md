### Title
Unfiltered PR label names become arbitrary env var keys (including `LD_PRELOAD`) reaching `PTY.spawn` via `TaskCommands#install_dependencies` - (File: `app/models/shipit/review_stack.rb`, `lib/shipit/task_commands.rb`, `lib/shipit/command.rb`)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) as an environment variable key with value `"true"`, with no allowlist of permitted keys. [1](#0-0)  `TaskCommands#env` merges `@stack.env` directly into the env hash used to build `Command` objects for `install_dependencies`, without ever calling any `filter_*_envs`/`EnvironmentVariables#permit` allowlist on it. [2](#0-1)  That hash ultimately reaches `PTY.spawn` unmodified except for stringification and merging over `BASE_ENV`. [3](#0-2) 

### Finding Description
The broken binding: the set of keys in the env hash passed to `PTY.spawn` should equal `deploy_spec.machine_env.keys ∪ declared_variable_definition_names`, but in practice it equals `BASE_ENV.keys ∪ {'PATH'} ∪ stack.env.keys ∪ {...fixed task keys...} ∪ deploy_spec.machine_env.keys ∪ task.env.keys`, where `stack.env.keys` for a `ReviewStack` includes every PR label name uppercased with no allowlist.

- `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim from the webhook payload onto the `PullRequest` record. [4](#0-3) 
- `ReviewStack#env` turns each label name into an uppercased env key mapped to `"true"`, merged over the base `Stack#env`. [1](#0-0) 
- `TaskCommands#env` merges `@stack.env` (the `ReviewStack#env` result for review-stack tasks) directly into the env used for both `install_dependencies` and `perform`, with no key restriction; only after this point does it merge fixed keys, `deploy_spec.machine_env`, and `@task.env`. [5](#0-4) 
- `Command#initialize` simply stores `env` (stringifying values), and `unbundled_env` merges `@env.stringify_keys` over `BASE_ENV` with no key filtering at all — there is no allowlist check like `EnvironmentVariables#permit` anywhere in this path. [6](#0-5) [7](#0-6) 
- `Command#start` passes that merged hash straight to `PTY.spawn`. [8](#0-7) 

The allowlist mechanism that does exist, `EnvironmentVariables#permit` (`sanitize_env_vars` against `variable_definitions.map(&:name)`), is only invoked via `DeploySpec#filter_task_envs` / `filter_deploy_envs` / `filter_rollback_envs`, and those are applied only to the caller-supplied `env:` argument at `Stack#trigger_task` / `Stack#build_deploy` time (to sanitize `task.env`) — never to `stack.env` itself. [9](#0-8)  Consequently a label such as `LD_PRELOAD` (case-insensitively converted to `LD_PRELOAD` since `.upcase` on that string is a no-op) becomes a literal `LD_PRELOAD=true` environment entry that reaches the `ruby`/`bundle` dependency-installation `Command` and is inherited by `PTY.spawn`. While the label value forced by the code is fixed to `"true"` rather than an attacker-chosen path (so a working `.so` payload path can't be injected through label *value*, only the *key* is attacker-controlled), the finding as stated is about **key injection with no allowlist**, which is confirmed: any label name becomes an unrestricted env key.

### Impact Explanation
An attacker who can label their own pull request (per the threat model given) can inject an arbitrary environment variable key into every dependency-installation and task command run for that review stack, including `LD_PRELOAD`, `RUBYOPT`, `BUNDLE_*`, `GEM_HOME`, etc. This affects the deploy host process spawned for that specific review stack/PR (blast radius limited to the review stack triggered by that PR, not other tenants directly, since `env` is scoped per-`Stack` instance). Because the value is hardcoded to `"true"` by `ReviewStack#env`, `LD_PRELOAD=true` alone does not point to a valid shared object and will not achieve preload-based RCE as literally described; achieving actual code execution would additionally require control over the *value*, which this code path does not grant. The demonstrable impact is therefore "arbitrary env-key injection with no allowlist," not full RCE via `LD_PRELOAD` value control.

### Likelihood Explanation
Preconditions: the target repository must have Shipit review-stack provisioning enabled and a `PullRequest`/`ReviewStack` already created; per the stated threat model, PR authors can label their own PRs. No secrets, tokens, or elevated GitHub permissions are required under the rules given. The step is trivially repeatable for any PR against any review-stack-enabled repository.

### Recommendation
Add an explicit allowlist to `ReviewStack#env` (and generally to any env merge sourced from untrusted webhook data) restricting label-derived keys to a small, safe, pre-declared prefix/set (e.g., only keys matching `/^LABEL_/` or explicitly declared `VariableDefinition`s), and reject/drop any label name colliding with security-sensitive variable names (`LD_PRELOAD`, `RUBYOPT`, `BUNDLE_*`, `PATH`, `GEM_HOME`, etc.). Apply `EnvironmentVariables#permit` against the deploy spec's `machine_env`/declared variable names to `stack.env` before it is merged in `TaskCommands#env`, not just to `task.env`.

### Proof of Concept
minitest plan (no live GitHub required):
1. Build a `Repository` + `ReviewStack` + `PullRequest` fixture; set `pull_request.labels = ['LD_PRELOAD']`.
2. Assert `stack.env['LD_PRELOAD'] == 'true'` (binding LHS: `ReviewStack#env` output includes attacker key; RHS expectation: it should be filtered out by an allowlist — currently they match, proving the vulnerability).
3. Build a `Task`/`TaskCommands.new(task)` against that stack; call `task_commands.env` and assert `env.key?('LD_PRELOAD')` is `true`.
4. Call `TaskCommands#install_dependencies` (stub `deploy_spec.dependencies_steps!` to return `[['ruby', '-v']]`), grab the resulting `Command`, and assert `command.unbundled_env.key?('LD_PRELOAD')` is `true`, confirming the unfiltered key reaches the hash passed to `PTY.spawn`.

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

**File:** lib/shipit/task_commands.rb (L17-48)
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

    def steps
      @task.definition.steps
    end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/stack.rb (L139-159)
```ruby
    def trigger_task(definition_id, user, env: nil, force: false)
      definition = find_task_definition(definition_id)
      env = env.to_h

      definition.variables_with_defaults.each do |variable|
        env[variable.name] ||= variable.default
      end

      commit = last_deployed_commit.presence || commits.first
      task = tasks.create(
        user_id: user.id,
        definition:,
        until_commit_id: commit.id,
        since_commit_id: commit.id,
        env: definition.filter_envs(env),
        allow_concurrency: definition.allow_concurrency? || force,
        ignored_safeties: force
      )
      task.enqueue
      task
    end
```
