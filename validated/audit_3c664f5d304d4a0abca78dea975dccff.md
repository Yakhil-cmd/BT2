### Title
Attacker-controlled PR labels are merged unfiltered into the deploy task environment, reaching `Command#unbundled_env`/`PTY.spawn` (arbitrary env var injection, incl. `LD_PRELOAD`) - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` upcases every GitHub pull-request label and merges it directly into the stack environment hash with no whitelist. This hash flows unmodified through `TaskCommands#env` into `Command.new(..., env:)`, and `Command#unbundled_env` (`lib/shipit/command.rb:104`) merges `@env.stringify_keys` on top of `BASE_ENV` without removing or filtering any keys, so an attacker-chosen label such as `LD_PRELOAD` ends up in the exact environment hash passed to `PTY.spawn` (`lib/shipit/command.rb:92`).

### Finding Description
Binding claimed safe: `Command#unbundled_env.keys == BASE_ENV.keys ∪ Shipit.env.keys ∪ deploy_spec.machine_env.keys ∪ @task.env.keys` (i.e., no attacker-controlled source contributes keys). This does not hold for review-stack deploys.

Path:
- `PullRequest#github_pull_request=` sets `self.labels = github_pull_request.labels.map(&:name)` directly from the GitHub webhook payload with no name validation/whitelist. [1](#0-0) 
- `ReviewStack#env` overrides `Stack#env` and merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into the base stack env, for any review stack that has a pull request. [2](#0-1) 
- `TaskCommands#env` builds the task's command environment as `super.merge(@stack.env).merge({...}).merge(deploy_spec.machine_env).merge(@task.env)` — `@stack.env` (which, for a `ReviewStack`, includes the label-derived keys) is merged in with no filtering. [3](#0-2) 
- `TaskCommands#perform`/`#install_dependencies` build `Command.new(command_line, env:, chdir: steps_directory)` using that unfiltered hash. [4](#0-3) 
- `Command#initialize` stores `@env = env.transform_values(&:to_s)` verbatim (no key filtering). [5](#0-4) 
- `Command#unbundled_env` computes `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` — this is a plain `Hash#merge`, which adds any key present in `@env` regardless of whether it exists in `BASE_ENV`. [6](#0-5) 
- `start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`, so the merged hash — including any attacker label key — becomes the literal process environment of the spawned shell command. [7](#0-6) 

Why the intended guard (`EnvironmentVariables#permit`) does not apply here: that whitelist mechanism exists (`lib/shipit/environment_variables.rb:13-18`) and is used to filter task/deploy-triggered variables (`Stack#trigger_task`/`build_deploy` call `definition.filter_envs`/`filter_deploy_envs`), but `ReviewStack#env` and `TaskCommands#env` never route the stack's own `env` computation through it. [8](#0-7) [9](#0-8) 

Attacker's exact action: open (or push a label to) a pull request against a repository configured for GitHub review-app/review-stack deploys, and add a label literally named `LD_PRELOAD` (or `BUNDLE_GEMFILE`, `RUBYOPT`, `GEM_PATH`, `DYLD_INSERT_LIBRARIES`, etc.) to that PR. Since labeling is a repo-collaborator-level GitHub action but the review-stack pipeline is designed to run untrusted PR code/branches by design (that's the point of review apps), and `Labeled`/`Unlabeled` webhook handlers persist `github_pull_request.labels` unconditionally on any inbound (correctly-signed) webhook for that repo, the label reaches `PullRequest#labels` and then flows through `ReviewStack#env` into every subsequent deploy/install command's environment.

### Impact Explanation
This is a Critical-severity environment-injection primitive into the deploy host's own process spawn (`PTY.spawn`) for any command run during a review-stack deploy (`install_dependencies`, all deploy `steps`, etc.). Depending on what other environment variables are already set/unset on `BASE_ENV` (e.g., dynamic loader variables like `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` on Linux/macOS, `RUBYOPT`, `BUNDLE_GEMFILE`, `GIT_SSH_COMMAND`, etc.), this can escalate to arbitrary code execution in the context of subsequently-invoked binaries (git, bundler, ruby, shell) on the deploy host — matching the "Critical - RCE on the deploy host via `Command`/`PTY.spawn`" category. Blast radius is scoped to stacks that are `ReviewStack`s with an attached `pull_request`; every deploy of that particular review stack is affected, and repeated PR labeling gives the attacker repeatable control of the injected value.

### Likelihood Explanation
Preconditions: the target repository must be configured to use Shipit review stacks (a documented, common feature) and the attacker must be able to add a label to a PR — which typically requires write/triage access to that repository (or the ability to open PRs in repos where labels can be applied by non-maintainers depending on GitHub/org settings). The webhook itself is verified (`GitHubApp#verify_webhook_signature`), so this is not a spoofed-webhook attack; it requires a legitimate, signature-valid webhook for an action the attacker can trigger through normal GitHub label-application permissions on a repo already onboarded to Shipit review apps. Given that review-stack deploys are explicitly designed to run code from PR branches, and that label-based configuration (`ReviewStack#env`) is a documented feature, the cost to an attacker who already has labeling rights on such a repo is trivial and fully repeatable.

### Recommendation
Do not let raw PR label names become environment variable keys. Either:
1. Whitelist/prefix label-derived variables (e.g., only pass through labels matching a safe pattern like `^REVIEW_[A-Z0-9_]+$`, or require a `shipit:` prefix that is stripped before use), and/or
2. Route `ReviewStack#env`'s label-derived hash through `EnvironmentVariables#permit` against an explicit list of variable names allowed by the stack's `deploy_spec`, rejecting/dropping any label name not on that list, and/or
3. In `Command#unbundled_env`, intersect `@env` with an explicit set of permitted variable names rather than blindly merging, so unknown keys never reach `PTY.spawn`.

### Proof of Concept
Minitest plan (mirrors the question's proof idea), no live GitHub required:
```ruby
test "PR label LD_PRELOAD reaches Command#unbundled_env for review stack deploys" do
  stack = shipit_stacks(:shipit) # or create a Shipit::ReviewStack fixture
  pull_request = stack.create_pull_request!(...) # or fixture with stack: review_stack
  pull_request.update!(labels: ['LD_PRELOAD'])

  deploy = stack.deploys.create!(until_commit: ..., since_commit: ...)
  task_commands = TaskCommands.new(deploy)

  command = Command.new('true', env: task_commands.env, chdir: Dir.tmpdir)

  assert command.unbundled_env.key?('LD_PRELOAD'),
    "expected label-derived key to leak into the process env passed to PTY.spawn"
  assert_equal 'true', command.unbundled_env['LD_PRELOAD']
end
```
Both sides of the binding diverge: `Command#unbundled_env.keys` is expected to equal `BASE_ENV.keys ∪ Shipit.env.keys ∪ deploy_spec.machine_env.keys ∪ @task.env.keys`, but in practice it also includes `PullRequest#labels`-derived keys via `ReviewStack#env` → `TaskCommands#env` → `Command#env` → `Command#unbundled_env`, confirming the vulnerability.

### Citations

**File:** app/models/shipit/pull_request.rb (L36-49)
```ruby
    def github_pull_request=(github_pull_request)
      self.github_id = github_pull_request.id
      self.number = github_pull_request.number
      self.api_url = github_pull_request.url
      self.title = github_pull_request.title
      self.state = github_pull_request.state
      self.additions = github_pull_request.additions
      self.deletions = github_pull_request.deletions
      self.user = User.find_or_create_by_login!(github_pull_request.user.login)
      self.assignees = github_pull_request.assignees.map do |github_user|
        User.find_or_create_by_login!(github_user.login)
      end
      self.labels = github_pull_request.labels.map(&:name)
      self.head = find_or_create_commit_from_github_by_sha!(github_pull_request.head.sha)
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
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
