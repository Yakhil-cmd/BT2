Confirmed: `steps_directory` (the `chdir` for each `Command`) is `@task.working_directory`, the attacker's own checked-out branch content, giving the attacker full control over the directory tree used to resolve relative `PATH` entries.

### Title
Review-stack PR labels can overwrite `PATH` via `ReviewStack#env` → `Command#unbundled_env`, enabling RCE on the deploy host - (File: `app/models/shipit/review_stack.rb`, `lib/shipit/command.rb`)

### Summary
`Shipit::ReviewStack#env` merges every pull-request label (upcased) as an environment variable with no name denylist, and `Shipit::Command#unbundled_env` merges the caller-supplied `@env` last, after computing `PATH` from `Shipit.shell_paths`. An attacker who can label their own PR (no Shipit privileges required) can set a label literally named `path`/`PATH`, which becomes `ENV['PATH'] = 'true'` for every command of the next deploy/task run on that review stack, and combined with attacker-controlled repo content in the checkout directory (`@task.working_directory`, used as `chdir`), this yields relative-path binary hijacking / RCE on the deploy host.

### Finding Description
The broken binding: the set of keys `Shipit.shell_paths` computes and injects as `PATH` in `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) should be disjoint from the set of keys an unauthenticated PR label can supply via `pull_request.labels` — i.e. `{'PATH'} ∩ keys(pull_request.labels.map(&:upcase))` should be `∅`, but it is not.

Path:
1. Attacker opens a PR against a repo with `Shipit.review_stacks?`/`review_stacks_enabled` on, and a `Shipit::ReviewStack` + `Shipit::PullRequest` exist for it (`app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:72-85`).
2. Attacker adds a label literally named `PATH` to their own PR via the GitHub UI, firing a `labeled` webhook.
3. `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler#process` → `#capture_labels?` → `labeled_active_stack?` (true for any non-archived stack, no maintainer check) → `#capture_labels` calls `pull_request.update!(labels: params.pull_request.labels.map(&:name))` with no denylist of names (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:62-64,98-102`).
4. On the next deploy/task, `Shipit::ReviewStack#env` does `super.merge(pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" })` (`app/models/shipit/review_stack.rb:84-93`) — this produces `{'PATH' => 'true', ...}` with no name filtering.
5. `Shipit::TaskCommands#env` does `super.merge(@stack.env).merge({SHIPIT_USER:..., EMAIL:..., BUNDLE_PATH:..., ...}).merge(deploy_spec.machine_env).merge(@task.env)` (`lib/shipit/task_commands.rb:33-48`). `PATH` is **not** among the keys re-asserted in the explicit hash that follows `@stack.env`, so the attacker's `PATH='true'` survives to the final `env` hash used to build every `Shipit::Command` for the deploy/task steps.
6. `Shipit::Command#initialize` stores `@env = env.transform_values(&:to_s)` unfiltered (`lib/shipit/command.rb:31-37`); `Command#unbundled_env` computes `BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)` (`lib/shipit/command.rb:103-105`) — the attacker's `@env['PATH']` is merged **last**, overwriting the computed `PATH`.
7. `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` with `@chdir` being `@task.working_directory`/`steps_directory` (`lib/shipit/task_commands.rb:92-98`), which is the checkout of the attacker's own PR branch content.

Existing guards do not catch this: `EnvironmentVariables#permit` (`lib/shipit/environment_variables.rb`) is only applied to explicitly user-submitted API params (`filter_deploy_envs`, `filter_rollback_envs`, `TaskDefinition#filter_envs`), never to `@stack.env`/label-derived env merged inside `TaskCommands#env`. `LabelCapturingHandler`'s `params` schema (`ExplicitParameters`) validates types/presence only, not label name content. No model validation on `Shipit::PullRequest#labels` (plain serialized array, `app/models/shipit/pull_request.rb:14`) restricts reserved names.

### Impact Explanation
Every subsequent step `Command` in the next deploy/task for that review stack executes with `PATH='true'` instead of the intended `"#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"`. Since `'true'` is a relative path component resolved against `chdir` (the attacker's own checked-out branch), any executable the attacker commits under a `true/` directory in their PR branch (e.g. `true/bundle`, `true/git`, `true/sh`) whose name matches a step command will be executed instead of the legitimate binary — Critical: RCE on the deploy host scoped to that stack, executed with the Shipit worker's privileges (which may include `GITHUB_TOKEN`/deploy secrets in the process environment). Blast radius is limited to review-stack-enabled repositories/stacks the attacker can open PRs against, but is fully attacker-repeatable per stack per deploy.

### Likelihood Explanation
Preconditions are low-cost and entirely within an unprivileged attacker's control: `Shipit.review_stacks?`/`repository.review_stacks_enabled` must be true (a documented, common feature), and any GitHub user able to open a PR against that repo can label their own PR — no Shipit session, API token, or GitHub team membership needed. The only additional requirement for full RCE (vs. broken command resolution) is that a step invoke a bare command name matching a file the attacker planted in `true/` in their own PR branch, which the attacker fully controls. This is trivially repeatable against any repository with review stacks enabled.

### Recommendation
In `Shipit::ReviewStack#env`, reject/skip label names that collide with reserved/system environment variable names (at minimum `PATH`, and ideally an explicit denylist or allowlist similar to `EnvironmentVariables#permit`) before merging. Additionally, in `Shipit::Command#unbundled_env`, do not allow caller-supplied `@env['PATH']` to fully replace the computed `PATH`; either strip `PATH` from `@env` before merging or prepend `Shipit.shell_paths`/`ENV['PATH']` after merging so it cannot be fully overridden by injected env values.

### Proof of Concept
```ruby
# test/unit/command_test.rb (new test)
test "#unbundled_env does not let a caller-supplied PATH override Shipit.shell_paths" do
  command = Command.new('true', env: { 'PATH' => 'true' }, chdir: '.')
  computed_path = "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"
  assert_equal 'true', command.unbundled_env['PATH']       # current (vulnerable) behaviour
  refute_equal computed_path, command.unbundled_env['PATH'] # PATH from Shipit.shell_paths is lost
end

# test/models/shipit/review_stack_test.rb (new test)
test "#env allows a 'PATH' label to overwrite the PATH env var" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ['PATH']
  assert_equal 'true', stack.env['PATH']
end
```
Both assertions demonstrate the equality `Shipit.shell_paths`-derived `PATH` == attacker-controlled `pull_request.labels`-derived `PATH` holds where it should not (should be `∅` intersection), confirming the vulnerability without any live GitHub interaction. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L62-102)
```ruby
          def labeled_active_stack?
            labeled? && stack.present? && !stack.archived?
          end

          def unlabeled_active_stack?
            unlabeled? && stack.present? && !stack.archived?
          end

          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
          end

          def opened?
            action == "opened"
          end

          def labeled?
            action == "labeled"
          end

          def unlabeled?
            action == "unlabeled"
          end

          def reopened?
            action == "reopened"
          end

          def action
            params.action
          end

          def pull_request
            params.pull_request
          end

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

**File:** lib/shipit/task_commands.rb (L92-98)
```ruby
    def steps_directory
      if sub_directory = deploy_spec.directory.presence
        File.join(@task.working_directory, sub_directory)
      else
        @task.working_directory
      end
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

**File:** app/models/shipit/pull_request.rb (L14-14)
```ruby
    serialize :labels, coder: Shipit.serialized_column(:labels, type: Array)
```
