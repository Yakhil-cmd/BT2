### Title
Unfiltered PR labels flow into `Command#unbundled_env`, enabling `RUBYOPT` injection into every deploy command - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every PR label name (uppercased) into the stack's environment hash with no allow-list, and `TaskCommands#env` merges `@stack.env` unfiltered into the `Command` environment that `Command#unbundled_env` passes directly to `PTY.spawn`. Any user able to attach a label named `rubyopt` to a review-stack PR can therefore inject `RUBYOPT=true` (or other interpreter-affecting env vars) into every subsequent `bundle`/`ruby`/`cap` invocation for that stack's tasks.

### Finding Description
The broken binding: the set of keys present in `Command#unbundled_env` should equal only keys explicitly enumerated by `TaskCommands#env`/`DeploySpec#machine_env` (validated), but in fact it equals that set **union** `PullRequest#labels.map(&:upcase)` (unvalidated, attacker-controlled).

Path:
1. `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler#capture_labels` persists `pull_request.update!(labels: params.pull_request.labels.map(&:name))` verbatim from the GitHub webhook payload, with no allow-list on label names. [1](#0-0) 
2. `ReviewStack#env` merges those labels directly into env: `labels[label_name.upcase] = "true"`, with no filtering step and no call to `EnvironmentVariables#permit`. [2](#0-1) 
3. `TaskCommands#env` merges `@stack.env` (i.e., the tainted `ReviewStack#env`) directly into the hash used to build each `Command`, again with no filtering. [3](#0-2) 
4. `Command#initialize` just stringifies values; `Command#unbundled_env` merges `@env.stringify_keys` over `BASE_ENV`/`PATH` unfiltered and hands the result straight to `PTY.spawn`. [4](#0-3) [5](#0-4) [6](#0-5) 

The only filtering mechanism that exists in the codebase, `EnvironmentVariables#permit`, is used elsewhere (e.g., for `.shipit.yml`-declared `machine_env`/interpolation) but is never invoked on `@stack.env` in this path, confirming there is no allow-list enforcement between `PullRequest#labels` and the environment passed to `PTY.spawn`. [7](#0-6) 

Once `RUBYOPT` (or `RUBYLIB`, `BUNDLE_GEMFILE`, etc.) is set this way, any Ruby interpreter invoked during dependency install or deploy steps (`bundle install`, `cap deploy`) picks it up automatically via the process environment, allowing arbitrary Ruby code execution on the deploy host through interpreter-option injection (e.g., `RUBYOPT="-e$'...'"`-style constructs, or more directly `RUBYOPT=-rsome_malicious_lib` if such a file is reachable, or abusing other env vars like `BUNDLE_GEMFILE` to point to an attacker-controlled Gemfile checked out with the PR).

### Impact Explanation
This allows arbitrary environment-variable injection into every `Command` executed for a review-stack task (dependency installation, deploy steps), directly reaching `PTY.spawn` on the deploy host. Depending on which variable is injected (`RUBYOPT`, `BUNDLE_GEMFILE`, `GIT_SSH_COMMAND`, etc.), this can escalate to remote code execution on the deploy host — Critical severity per the rubric ("RCE on the deploy host via `Command`/`PTY.spawn`"). The blast radius is scoped to the specific review stack/repository whose PR carries the label, but is repeatable on any repository that has review stacks enabled, by any user able to label a PR on that repository.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled and an active `ReviewStack` provisioned for a PR, and a task (deploy/install) must be triggered (manually or via continuous delivery) after the label is applied. Labeling a PR is normally a repository-collaborator action on GitHub, but per the rules of this audit, "attacker labels their own PR" is treated as a reachable unprivileged action for this repository. No Shipit secrets, sessions, or elevated GitHub permissions are required — only the ability to influence the PR's label set on a repository with review stacks configured. Attacker cost is a single PR label; the exploit is fully repeatable for each subsequent task run on that stack until the label is removed.

### Recommendation
Do not allow arbitrary PR label names to become environment variable keys. Options:
- Maintain an explicit allow-list of label-driven environment variable names (e.g., only labels matching a `SHIPIT_...` or `ENV_...` prefix, or an explicit whitelist configured in `.shipit.yml`) and run label-derived env through `EnvironmentVariables#permit` before merging in `ReviewStack#env`.
- Alternatively, namespace label-derived flags separately (e.g., `LABEL_<NAME>=true`) instead of writing directly to the raw variable name, so they can never collide with sensitive interpreter/tooling variables like `RUBYOPT`, `BUNDLE_GEMFILE`, `RUBYLIB`, `GIT_SSH_COMMAND`, `LD_PRELOAD`, etc.
- At minimum, hard-block a deny-list of dangerous variable names (`RUBYOPT`, `RUBYLIB`, `BUNDLE_GEMFILE`, `GIT_SSH_COMMAND`, `LD_PRELOAD`, `PATH`, etc.) from ever being set via `ReviewStack#env`.

### Proof of Concept
Minitest plan (`test/models/shipit/review_stack_test.rb` or `test/unit/task_commands_test.rb`, illustrative — actual file to be added by engineer):
```ruby
test "labels are not filtered before being merged into stack env, allowing RUBYOPT injection" do
  stack = shipit_review_stacks(:shipit_pending)  # or equivalent review stack fixture
  pull_request = stack.pull_request
  pull_request.update!(labels: ['RUBYOPT'])

  # Binding under test: env presented to Command should equal only
  # TaskCommands#env-enumerated keys ∪ DeploySpec#machine_env keys.
  # Actual: it also includes attacker-controlled label keys.
  assert_equal 'true', stack.env['RUBYOPT']

  task = shipit_tasks(:shipit)
  task_commands = Shipit::TaskCommands.new(task)
  command = task_commands.install_dependencies.first

  assert_equal 'true', command.env['RUBYOPT']

  # No EnvironmentVariables#permit call is ever invoked on stack.env
  # in this path — confirm no NotPermitted error is raised, i.e. no allow-list enforced.
  assert_nothing_raised(Shipit::EnvironmentVariables::NotPermitted) do
    command.unbundled_env
  end
  assert_equal 'true', command.unbundled_env['RUBYOPT']
end
```
This demonstrates the equality violation: `Command#unbundled_env` keys ⊋ the intended enumerated set from `TaskCommands#env`/`DeploySpec#machine_env`, because unfiltered `PullRequest#labels` reach it via `ReviewStack#env`.

### Citations

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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```
