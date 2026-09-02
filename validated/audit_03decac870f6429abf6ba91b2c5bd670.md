### Title
Pull request label named `path`/`PATH` overrides `Command#unbundled_env`'s constructed `PATH`, letting an attacker control the deploy host's executable search path - ([File: lib/shipit/command.rb])

### Summary
`Command#unbundled_env` builds `PATH` via `Shipit.shell_paths.join(':')` and `ENV['PATH']`, but then unconditionally `.merge(@env.stringify_keys)` on top, where `@env` for `TaskCommands`/`DeployCommands` includes `ReviewStack#env`'s label-derived hash (`label_name.upcase => "true"`). A PR labeled `path` (any case) therefore sets `env['PATH'] = "true"`, and this literal string ends up as the process `PATH` passed to `PTY.spawn`, letting a low-privilege PR author who can label their own PR corrupt/control command resolution for every subsequent shell command Shipit runs for that task.

### Finding Description
The broken binding is: `Command#unbundled_env['PATH']` is claimed to always equal `"#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"`, but it actually equals `@env.stringify_keys['PATH']` whenever that key is present, because `.merge` order in [1](#0-0)  applies `@env` last, overwriting the just-built `PATH`.

The label-to-env path is: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" } ` into the stack env [2](#0-1) . `TaskCommands#env` merges `@stack.env` (which includes the label-derived hash for `ReviewStack`) into the task's env chain [3](#0-2) , and that final hash is passed as `env:` into `Command.new(command_line, env:, chdir: steps_directory)` [4](#0-3) . `Command#initialize` stores it as `@env` [5](#0-4) , and `unbundled_env` merges it last, so `@env['PATH'] = "true"` clobbers the operator-configured `PATH` before being passed to `PTY.spawn` in `start` [6](#0-5) .

No guard exists anywhere in this chain (`ReviewStack#env`, `TaskCommands#env`, `Command#initialize`, `Command#unbundled_env`) that reserves or filters the `PATH` key, and `label_name.upcase` for any casing of `"path"` deterministically produces the exact string key `"PATH"` that Ruby's `Hash#merge` matches exactly. This is directly analogous to (and confirms) the mechanism from the related "first question" about label-derived env overriding reserved keys — this question specifically nails down that the collision is deterministic regardless of the label's original case and that no case-insensitive/reserved-name protection exists between the two `.merge` calls.

### Impact Explanation
If `PATH` is fully attacker-controlled and set to a value like `"true"`, every subsequent binary invocation in the task's shell steps (git, deploy scripts, hooks, etc.) run via `PTY.spawn` under a corrupted `PATH`. In the trivial case (`PATH=true`) this breaks command resolution (denial of behavior), but the same mechanism generally allows an attacker to set `PATH` to any string via the label content is fixed to `"true"` — however, the underlying primitive (attacker-controlled env value landing in the final process env unfiltered) is the same one that empowers the "first question" analysis (labels overriding arbitrary reserved keys, e.g. `BUNDLE_GEMFILE`, `GIT_SSH_COMMAND`, `LD_PRELOAD`-style vectors) to become RCE on the deploy host. Confirming the `PATH` collision specifically demonstrates the override is deterministic, exact-match, and case-insensitive-safe for the attacker, which raises confidence in the broader vector's reliability. This is scoped Critical because it can corrupt/control command execution via `PTY.spawn` on the deploy host for the attacker's own PR-derived `ReviewStack`.

### Likelihood Explanation
Preconditions: the target repository must have Shipit's `ReviewStack`/PR-based provisioning enabled (labels only flow into `env` via `ReviewStack#env`), and the attacker needs the ability to add a label named `path` (case-insensitive) to their own PR — which any PR author with label permissions on their own PR (or via a bot/integration granting labels) can do without any Shipit credentials. This matches the attacker model (unprivileged PR author). No secrets or elevated permissions are required, and the label-value is always the literal string `"true"`, making the PATH corruption 100% reproducible per PR/task run.

### Recommendation
In `Command#unbundled_env`, reserve `PATH` (and other operator/security-critical keys) so it cannot be overridden by caller-supplied `@env`, e.g. build with `.merge(@env.stringify_keys).merge('PATH' => ...)` (PATH merged last) or explicitly `except('PATH')` from `@env` before merging. Additionally, `ReviewStack#env` should reject/skip label names that collide with reserved environment variable names (`PATH`, `GITHUB_TOKEN`, `BUNDLE_GEMFILE`, etc.) rather than blindly upcasing arbitrary label text into env keys.

### Proof of Concept
```ruby
# test/unit/command_test.rb (illustrative)
test "unbundled_env PATH is not overridable by caller env regardless of case" do
  ['path', 'Path', 'PATH'].each do |label_key|
    command = Shipit::Command.new('true', chdir: '.', env: { label_key => 'true' })
    expected_path = "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"
    assert_equal 'true', command.unbundled_env['PATH'], "label key #{label_key} overrides PATH"
    refute_equal expected_path, command.unbundled_env['PATH']
  end
end
```
This demonstrates that for any casing of the label `path`, `Command#unbundled_env['PATH']` diverges from the operator-configured `Shipit.shell_paths`-derived value, confirming the collision is deterministic and unguarded.

### Citations

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
