### Title
Unfiltered PR label injection into deploy environment enables Ruby `$LOAD_PATH` / env hijack via `PTY.spawn` - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` converts every GitHub PR label name directly into an environment variable (`LABEL_NAME => "true"`) with no allow-list filtering, and this hash is merged unconditionally into the environment passed to `Command#unbundled_env`/`PTY.spawn` for every task run against that review stack. An attacker who controls a pull request (and thus its labels, via GitHub's labeling flow) and the corresponding branch content can inject arbitrary environment variable names — including `RUBYLIB`, `BUNDLE_GEMFILE`, or even `PATH` — into every Ruby/Bundler/Capistrano deploy step executed for that stack.

### Finding Description
The question's claimed binding is: `Command#unbundled_env` keys == `deploy_spec.machine_env` / `VariableDefinition`-permitted keys. Tracing the actual code shows this binding is **false**:

- `PullRequest#github_pull_request=` stores GitHub PR labels verbatim: `self.labels = github_pull_request.labels.map(&:name)` [1](#0-0) .
- `LabelCapturingHandler#capture_labels`, triggered on `labeled`/`unlabeled`/`opened`/`reopened` pull_request webhook events, persists these attacker-supplied label names onto the stack's `pull_request` record with `pull_request.update!(labels: params.pull_request.labels.map(&:name))` [2](#0-1) .
- `ReviewStack#env` then unconditionally merges these labels into the stack env, using the **uppercased label name as the env var key** and the literal string `"true"` as the value, with no filtering through `deploy_variables`/`VariableDefinition`/`EnvironmentVariables#permit`: [3](#0-2) .
- `TaskCommands#env` merges `@stack.env` (i.e., this unfiltered hash) directly into the task's environment, alongside `deploy_spec.machine_env` (which *is* the legitimately scoped source), with no filtering applied to the stack portion: [4](#0-3) .
- `Command#unbundled_env` merges `@env.stringify_keys` (the fully-merged, unfiltered task env) on top of `BASE_ENV`/`PATH`, and this is exactly what's passed to `PTY.spawn` in `Command#start`: [5](#0-4) .

None of the existing guards catch this: `filter_deploy_envs`/`filter_rollback_envs`/`EnvironmentVariables#permit` are only applied to `@task.env` (the caller-supplied deploy/rollback variables) at the point tasks/deploys are built in `Stack#trigger_task`/`Stack#build_deploy` [6](#0-5) , not to `Stack#env`/`ReviewStack#env`, which is a separate, always-merged source that bypasses `deploy_spec.machine_env`'s `VariableDefinition` allow-list entirely.

**Attack**: An attacker opens a PR against a repo with review stacks enabled, adds a label named `rubylib` (case-insensitive; becomes `RUBYLIB`) to their own PR (an action explicitly listed as available to the unprivileged attacker in this exercise), and includes in their branch a file/directory named `true` containing a malicious Ruby file matching a library name that a deploy/bundler-discovery step subsequently `require`s. When the review-stack deploy runs (`bundle install`, `bundle exec cap`, discovered dependency/deploy steps), `RUBYLIB=true` is injected into `$LOAD_PATH`, causing Ruby to search the attacker-controlled checkout directory for library files ahead of legitimate gems, enabling code execution on the deploy host.

### Impact Explanation
This is Critical: it results in code execution on the Shipit deploy host during an automated review-stack deploy step, driven entirely by attacker-controlled PR metadata (label name) and attacker-controlled repo content (the malicious library file in their own branch). It is repeatable on every deploy/dependency-install run for that review stack as long as the label remains applied, and is not limited to a single tenant if any repo onboarded to Shipit runs Ruby-based deploy steps for review stacks.

### Likelihood Explanation
Preconditions: the target repository must use Shipit review stacks with a Ruby/Bundler/Capistrano-based deploy pipeline (common default per the scenario). The attacker needs only the ability to open a PR and add a label to it, and to control the PR branch content — no Shipit credentials, GitHub App keys, or maintainer status are required. Cost is trivial (one PR, one label, one added file).

### Recommendation
Do not derive raw environment variable keys from PR labels. Either remove `ReviewStack#env`'s label-to-env-var mechanism, or route it through the same `VariableDefinition`/`EnvironmentVariables#permit` allow-list used for `deploy_variables`/`rollback_variables`, and additionally reject/blocklist environment-variable names with special interpreter significance (`RUBYLIB`, `PATH`, `LD_PRELOAD`, `BUNDLE_GEMFILE`, etc.) regardless of source.

### Proof of Concept
Minitest plan (`test/models/shipit/review_stack_test.rb` or `test/unit/task_commands_test.rb`, existing test infra, no live GitHub):
1. Create a `ReviewStack` with an associated `PullRequest` whose `labels` include `"rubylib"`.
2. Assert the broken binding directly:
   - `assert stack.env.key?('RUBYLIB')` (currently true — proves `ReviewStack#env` leaks the label unfiltered).
   - `assert_equal 'true', stack.env['RUBYLIB']`.
3. Build a `Task`/`TaskCommands.new(task)` against that stack and assert `TaskCommands.new(task).env.key?('RUBYLIB')` is `true` (currently), demonstrating the value reaches the merged task environment that flows into `Command#unbundled_env`/`PTY.spawn`.
4. After applying the fix, the same assertions should return `false`/`KeyError`, confirming `RUBYLIB` (and other non-allow-listed keys) can no longer be injected via PR labels.

### Citations

**File:** app/models/shipit/pull_request.rb (L48-48)
```ruby
      self.labels = github_pull_request.labels.map(&:name)
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

**File:** app/models/shipit/stack.rb (L139-172)
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

    def build_deploy(until_commit, user, env: nil, force: false, allow_concurrency: force)
      since_commit = last_deployed_commit.presence || commits.first
      deploys.build(
        user_id: user.id,
        until_commit:,
        since_commit:,
        env: filter_deploy_envs(env.to_h),
        allow_concurrency:,
        ignored_safeties: force || !until_commit.deployable?,
        max_retries: retries_on_deploy
      )
    end
```
