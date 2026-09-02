### Title
Unvalidated PR label names become raw environment variable names/values injected into `bundle install`'s `PTY.spawn` env, enabling RCE via `BUNDLE_GEMFILE` - (File: app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`Shipit::PullRequest::LabelCapturingHandler#capture_labels` persists GitHub PR label names verbatim with no name/format validation, and `Shipit::ReviewStack#env` upcases each label and injects it directly into the stack's environment hash with value `"true"`. This merged environment reaches `Shipit::TaskCommands#install_dependencies` and ultimately `Shipit::Command#unbundled_env`, which is passed straight to `PTY.spawn` with zero whitelist filtering, so a label literally named `BUNDLE_GEMFILE` sets that variable for the `bundle install` step.

### Finding Description
The broken binding: the question asserts `keys accepted by LabelCapturingHandler#capture_labels == keys deploy spec's VariableDefinition/machine_env whitelist permits into Command#unbundled_env`. Tracing the code shows this is not even an approximate equality — it's an *absence* of any whitelist on the install-dependencies path:

- `capture_labels` only validates `name` as a `String` in the webhook schema and writes it unchanged: `pull_request.update!(labels: params.pull_request.labels.map(&:name))` [1](#0-0) , gated only by `labeled_active_stack?` (stack present, not archived) [2](#0-1) .
- `ReviewStack#env` merges each label, upcased, as a key with a fixed `"true"` value into the stack's env hash [3](#0-2) .
- `TaskCommands#env` merges `@stack.env` directly into the task environment with **no call** to `filter_deploy_envs`/`EnvironmentVariables#permit` at all [4](#0-3) . That whitelist (`deploy_variables`/`VariableDefinition`) is only applied in `Stack#build_deploy` and `Stack#trigger_task` for user-supplied deploy/task env [5](#0-4) , never for the label-derived stack env consumed here.
- `install_dependencies` builds `Command.new(command_line, env:, chdir: steps_directory)` using this unfiltered env [6](#0-5) , and the default dependency steps for a bundler project are `bundle install` variants discovered by `BundlerDiscovery#bundle_install` [7](#0-6) .
- `Command#unbundled_env` merges `BASE_ENV` (derived from `Bundler.unbundled_env`/`clean_env`) with `@env.stringify_keys` (the attacker-controlled hash) and this exact hash is passed to `PTY.spawn` [8](#0-7) .
- `Commands#base_env`, inherited via `TaskCommands#env`'s `super`, includes `GITHUB_TOKEN` from `Shipit.github.token` [9](#0-8) , so the spawned `bundle install` process (and any Ruby code executed via a malicious `Gemfile` it loads) inherits that credential.

Exploit flow: attacker owns a repository/fork tracked by an existing, active `Shipit::ReviewStack` (a Shipit maintainer configuration precondition, not an attacker privilege). Attacker commits a file literally named `true` containing malicious Ruby (a valid Gemfile DSL/Ruby payload) to their PR branch, then applies a GitHub label named `BUNDLE_GEMFILE` to their own PR — an action fully within an unprivileged repository owner's capability on their own repo. GitHub sends a legitimately signed `labeled` webhook; `capture_labels` stores the label, `ReviewStack#env` turns it into `BUNDLE_GEMFILE=true`, and the next `install_dependencies` run for that stack spawns `bundle install` with `BUNDLE_GEMFILE=true` in env, causing Bundler to load the attacker's file named `true` as the Gemfile and execute arbitrary Ruby on the deploy host, in a process holding `GITHUB_TOKEN`.

Existing guards do not stop this: the webhook `params` schema only enforces label `name` is a `String` with no format restriction [10](#0-9) ; `EnvironmentVariables#permit`/`filter_deploy_envs` exist in the codebase but are never invoked on this code path [11](#0-10) [4](#0-3) ; and `Stack` model validations only constrain `environment`/`branch`/`deploy_url` formats, not `PullRequest#labels` content.

### Impact Explanation
Arbitrary Ruby code execution on the shared Shipit deploy host during the dependency-install phase of the attacker's own review stack task, running with Shipit's environment (`GITHUB_TOKEN`, `GITHUB_DOMAIN`, and other `Shipit.env` values) inherited by the spawned process, via `Shipit::Command#unbundled_env`/`PTY.spawn`. This is repeatable on every `labeled`/relabel event and does not require the attacker to compromise any Shipit secret — it matches the Critical category "RCE on the deploy host via Command/PTY.spawn" and "exfiltration of GITHUB_TOKEN...or deploy-time secrets." Blast radius is scoped to review stacks tracking the attacker's own PR/repo, but the exfiltrated `GITHUB_TOKEN` and host access could be leveraged further depending on token scope and host multi-tenancy.

### Likelihood Explanation
Preconditions: the target repository must already have an active, non-archived `Shipit::ReviewStack` tracking the attacker's PR (a maintainer/operator configuration, common for review-stack-enabled repos), and the dependency step discovery must resolve to `bundle install` (default for any repo with a `Gemfile`). Attacker cost is low: open a PR from an owned fork/branch, commit a file named `true`, and apply a label named `BUNDLE_GEMFILE` to their own PR — all actions available to any PR author with label permission on their own repository, requiring no Shipit credentials, session, or GitHub App keys. This is fully repeatable per labeled event.

### Recommendation
Do not derive raw environment variable keys from user-controlled GitHub label text. At minimum: (1) validate/sanitize label names in `capture_labels` (e.g., reject/allowlist characters, reject reserved/dangerous names like `BUNDLE_GEMFILE`, `BUNDLE_*`, `PATH`, `GITHUB_TOKEN`), and (2) run the label-derived portion of `ReviewStack#env` (and generally any env merged in `TaskCommands#env`) through `EnvironmentVariables#permit` against an explicit whitelist (e.g., extend `deploy_variables`/`machine_env` semantics) before it reaches `Command#unbundled_env`/`PTY.spawn`, exactly closing the gap where `filter_deploy_envs` is applied to task/deploy `env:` kwargs but not to the stack's own `env` method output.

### Proof of Concept
Add a minitest asserting the unfiltered propagation, e.g. in `test/models/shipit/webhooks/handlers/pull_request/label_capturing_handler_test.rb` and `test/unit/task_commands_test.rb`:
1. Stub a `labeled` webhook payload for an active, non-archived `ReviewStack`'s PR with `labels: [{name: "BUNDLE_GEMFILE"}]`, dispatch through `LabelCapturingHandler`, and assert `pull_request.reload.labels == ["BUNDLE_GEMFILE"]` (equality side A: attacker-controlled string, unmodified).
2. Instantiate `TaskCommands.new(task)` for that stack/task and assert `task_commands.env["BUNDLE_GEMFILE"] == "true"` (equality side B: same key now present as an env var, proving no whitelist intersection with `deploy_spec.deploy_variables`/`machine_env` occurred).
3. Assert directly that `deploy_spec.deploy_variables.map(&:name)` (the whitelist) does NOT include `"BUNDLE_GEMFILE"`, yet it is present in `task_commands.env`, demonstrating the claimed binding is false/absent.
4. Optionally instantiate `Shipit::Command.new("env", env: task_commands.env, chdir: tmp_dir).unbundled_env` and assert `["BUNDLE_GEMFILE"] == "true"` in the hash that would be passed to `PTY.spawn`, without executing an actual `bundle install`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L29-31)
```ruby
              requires :labels, Array do
                requires :name, String
              end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L62-64)
```ruby
          def labeled_active_stack?
            labeled? && stack.present? && !stack.archived?
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

**File:** lib/shipit/task_commands.rb (L17-21)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
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

**File:** app/models/shipit/deploy_spec/bundler_discovery.rb (L28-37)
```ruby
      def bundle_install
        install_command = %(bundle install --jobs 4 --retry 2)
        [
          remove_ruby_version_from_gemfile,
          (bundle_config_frozen if frozen_mode?),
          bundle_config_path,
          bundle_without_groups,
          install_command
        ].compact
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

**File:** lib/shipit/commands.rb (L37-50)
```ruby
    def base_env
      @base_env ||= begin
        env = Shipit.env.merge(
          'GITHUB_DOMAIN' => github.domain,
          'GITHUB_TOKEN' => github.token
        )

        if Shipit.use_git_askpass?
          env['GIT_ASKPASS'] = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s
        end

        env
      end
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
