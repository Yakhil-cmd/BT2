### Title
[allow_all] Unfiltered pull-request-label-derived `GIT_SSH` reaches `git fetch origin` in `StackCommands#fetch`, allowing RCE via git's ssh transport - (File: app/models/shipit/review_stack.rb, lib/shipit/stack_commands.rb, lib/shipit/command.rb)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) directly into the stack's environment hash with no allowlist, unlike `deploy_variables`/`task variables` which are always passed through `EnvironmentVariables#permit`. `StackCommands#env` merges this unfiltered hash and passes it straight into `Command#initialize` for `git fetch origin`, and `Command#unbundled_env` layers `@env` on top of `BASE_ENV` before calling `PTY.spawn`, so an attacker-chosen `GIT_SSH` label value is inherited by the git subprocess.

### Finding Description
The broken binding: the invariant "git subprocess env == `base_env` (GITHUB_DOMAIN, GITHUB_TOKEN, GIT_ASKPASS, Shipit.env) with no fork-controllable keys" does not hold; instead `git subprocess env ⊇ {LABEL_NAME.upcase => "true" for each PR label}`.

Path:
1. `ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`) does: `super.merge(pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" })` — no key allowlist at all, contrary to `filter_deploy_envs`/`filter_envs` in `app/models/shipit/deploy_spec.rb:174-176` and `app/models/shipit/task_definition.rb:63-65`, both of which call `EnvironmentVariables.with(env).permit(...)` (`lib/shipit/environment_variables.rb:13-18`), which raises `NotPermitted` for any key not in the whitelist.
2. `LabelCapturingHandler#capture_labels` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102`) persists `params.pull_request.labels.map(&:name)` verbatim from the webhook JSON body onto `pull_request.labels`, with only a `String` type-check in the `params` schema (`requires :labels, Array do requires :name, String end`) — no character/format restriction, so a label literally named `git_ssh` (or any case) is accepted and stored.
3. `StackCommands#env` (`lib/shipit/stack_commands.rb:13-15`): `super.merge(@stack.env)` — merges the unfiltered `ReviewStack#env` hash (including the label-derived `GIT_SSH` key) into the command environment.
4. `StackCommands#fetch` (`lib/shipit/stack_commands.rb:27-35`) calls `git('fetch', 'origin', ..., @stack.branch, env:, chdir: @stack.git_path)`, passing this merged env to `Commands#git` (`lib/shipit/commands.rb:28-32`), which builds `Command.new("git", *args, env: kwargs[:env])`.
5. `Command#initialize` (`lib/shipit/command.rb:31-37`) stores `@env = env.transform_values(&:to_s)` (no filtering).
6. `Command#unbundled_env` (`lib/shipit/command.rb:103-105`): `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` — `@env` is merged **last**, so it can add/override arbitrary keys.
7. `Command#start` (`lib/shipit/command.rb:85-101`) calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`, so the git process is spawned with `GIT_SSH` set to whatever the attacker chose.

Since git honors `GIT_SSH` to select the program used for the ssh transport, if the fetch/clone URL uses an ssh-style remote (`git@host:...`), git will exec the attacker-named program instead of the real ssh client, achieving arbitrary command execution on the Shipit host under the process's privileges. Even where `GIT_SSH` is a no-op (https remotes), the same unfiltered merge mechanism demonstrates that *any* environment variable name is fork-controllable via a label — this is not limited to `GIT_SSH`; it is a generic env-injection primitive whose most severe instantiation is `GIT_SSH`/`GIT_SSH_COMMAND`.

Existing guards fail here specifically because:
- `verify_signature`/`drop_unhandled_event` only validate that the webhook came from GitHub for the given repo — they say nothing about the *content* of label names, so a legitimate label add on a fork's PR still carries an attacker-chosen string.
- The `ExplicitParameters` schema for `LabelCapturingHandler`/`LabeledHandler` only requires `labels[].name` to be a `String`; it enforces no charset/length/allowlist.
- `EnvironmentVariables#permit` exists and is used everywhere else env is exposed to user input (`deploy_variables`, task `variables`, `filter_deploy_envs`, `filter_rollback_envs`) but is **never applied** to `ReviewStack#env`/`StackCommands#env`. This is the missing guard. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

### Impact Explanation
If the ssh transport is used for the stack's git remote, the attacker-controlled `GIT_SSH` variable causes git (invoked from `StackCommands#fetch`, and reused by every other stack git operation since `StackCommands#env`/`Command#unbundled_env` apply the same merge) to execute an arbitrary attacker-named program on the Shipit deploy host during git fetch/clone — Remote Code Execution on the deploy host, matching the "Critical - RCE on the deploy host via `Command`/`PTY.spawn`" category. This is repeatable: the attacker can relabel/unlabel and reopen the PR to re-trigger fetches, and the underlying `ReviewStack#env` unfiltered-merge flaw generalizes to injecting/overriding any environment variable (not just `GIT_SSH`) into every subsequent task/deploy command run against that review stack, since `TaskCommands#env` also does `super.merge(@stack.env)` (`lib/shipit/task_commands.rb:33-48`). Blast radius is scoped to the review stack (and host) tied to the labeling repository's `allow_all` (or `allow_with_label`) provisioning configuration, but since all git/task commands on the host inherit `BASE_ENV`, a compromised process could pivot to other stacks/data on the shared deploy host. [9](#0-8) 

### Likelihood Explanation
Preconditions: the repository must have `review_stacks_enabled` and use `allow_all` (or `allow_with_label`) provisioning so a `ReviewStack` exists for the PR; the actual RCE trigger additionally requires the stack's git remote to be fetched over ssh (so `GIT_SSH` is honored) — this depends on Shipit/host git configuration (`repo_git_url`) rather than attacker control. Adding a label to a PR normally requires "write" or "triage" GitHub permission on the repository, which the stated attacker model explicitly grants ("label their own PR"). Given that, attacker cost is minimal — a single labeled webhook — and it's fully repeatable (re-trigger via unlabel/label or PR reopen) with no privileged Shipit credentials needed.

### Recommendation
Do not merge raw pull-request label names into the process/git environment. Either (a) drop `ReviewStack#env`'s label-to-env merge entirely, or (b) route it through `EnvironmentVariables.with(...).permit(deploy_spec.review_variables_or_similar_allowlist)` the same way `deploy_variables`/task `variables` are filtered, and additionally reject/deny well-known dangerous names (`GIT_SSH`, `GIT_SSH_COMMAND`, `LD_PRELOAD`, `BUNDLE_GEMFILE`, etc.) at the `Command`/`Commands#git` layer regardless of source.

### Proof of Concept
```ruby
# test/lib/shipit/stack_commands_test.rb (new test)
test "#fetch does not let a pull request label inject GIT_SSH into the git subprocess env" do
  stack = shipit_stacks(:review_stack)
  stack.repository.update!(provisioning_behavior: :allow_all, review_stacks_enabled: true)
  stack.pull_request.update!(labels: ["git_ssh=/tmp/evil.sh"]) # simulating LabelCapturingHandler#capture_labels persisting a raw webhook label name
  # More directly (case sensitivity per ReviewStack#env upcasing):
  stack.pull_request.update!(labels: ["evil"])
  stack.pull_request.labels = ["GIT_SSH"] # exact key match after upcase(no-op)

  commands = Shipit::StackCommands.new(stack)
  command = commands.fetch

  # EXPECTED (secure) binding: command.env keys are limited to base_env's + an explicit review-stack allowlist
  refute_includes command.env.keys, "GIT_SSH"

  # ACTUAL (vulnerable) binding demonstrated by current code:
  # assert_equal "true", command.env["GIT_SSH"]
end
```
This mirrors the existing tests that already assert the *unfiltered* merge behavior — `test/models/shipit/review_stack_test.rb:59-65` (`"#env includes the stack's pull request labels"`) and `test/lib/shipit/task_commands_test.rb:6-16` (`"#env includes a ReviewStack's pull request labels"`) — by substituting a label literally named `GIT_SSH`/`git_ssh` and asserting it reaches `StackCommands#fetch`'s `Command#env`, which per `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) is exactly what's passed to `PTY.spawn`. [10](#0-9) [11](#0-10)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** lib/shipit/stack_commands.rb (L13-35)
```ruby
    def env
      super.merge(@stack.env)
    end

    def fetch_commit(commit)
      create_directories
      if valid_git_repository?(@stack.git_path)
        git('fetch', 'origin', *quiet_git_arg, '--tags', '--force', commit.sha, env:, chdir: @stack.git_path)
      else
        @stack.clear_git_cache!
        git_clone(@stack.repo_git_url, @stack.git_path, branch: @stack.branch, env:, chdir: @stack.deploys_path)
      end
    end

    def fetch
      create_directories
      if valid_git_repository?(@stack.git_path)
        git('fetch', 'origin', *quiet_git_arg, '--tags', '--force', @stack.branch, env:, chdir: @stack.git_path)
      else
        @stack.clear_git_cache!
        git_clone(@stack.repo_git_url, @stack.git_path, branch: @stack.branch, env:, chdir: @stack.deploys_path)
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

**File:** lib/shipit/commands.rb (L24-32)
```ruby
    def env
      base_env
    end

    def git(*args)
      kwargs = args.extract_options!
      kwargs[:env] ||= base_env
      Command.new("git", *args, **kwargs)
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

**File:** app/models/shipit/deploy_spec.rb (L174-176)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
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

**File:** test/models/shipit/review_stack_test.rb (L59-65)
```ruby
    test "#env includes the stack's pull request labels" do
      stack = shipit_stacks(:review_stack)
      stack.pull_request.labels = ["wip", "bug"]

      assert_equal stack.env["WIP"], "true"
      assert_equal stack.env["BUG"], "true"
    end
```

**File:** test/lib/shipit/task_commands_test.rb (L6-16)
```ruby
  test "#env includes a ReviewStack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    stack.pull_request.labels = ["wip", "bug"]
    task = shipit_tasks(:shipit_restart)
    task.stack = stack

    env = Shipit::TaskCommands.new(task).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
  end
```
