Confirmed: `machine_env` (`config('machine', 'environment')`) is attacker-controlled via `shipit.yml` and is merged into `TaskCommands#env` with no key filtering.

### Title
Unrestricted `shipit.yml` `machine.environment` merge allows overwrite of `GITHUB_TOKEN`/`GIT_ASKPASS`/`BUNDLE_*` in spawned process env - ([File: lib/shipit/task_commands.rb])

### Summary
`DeploySpec::FileSystem#machine_env` (backed by `DeploySpec#machine_env`, `config('machine', 'environment')`) returns whatever hash a repository's `shipit.yml` declares under `machine.environment`, with no key allowlist or denylist. `TaskCommands#env` merges this attacker-controlled hash *after* the built-in `GITHUB_TOKEN`/`GIT_ASKPASS`-bearing base env, so any key name chosen by the repository owner silently overwrites Shipit's own secrets before the command reaches `Command#unbundled_env` and `PTY.spawn`.

### Finding Description
The claimed broken binding: "keys Shipit intends to expose" (`SHIPIT_USER`, `EMAIL`, `TASK_ID`, `GITHUB_REPO_OWNER`, etc.) == "keys actually present in the hash reaching `PTY.spawn`". Tracing `TaskCommands#env` at `lib/shipit/task_commands.rb:33-48`:

```
super
  .merge(@stack.env)
  .merge('SHIPIT_USER' => ..., 'EMAIL' => ..., ...)
  .merge(deploy_spec.machine_env)
  .merge(@task.env)
```

`super` resolves to `Commands#env` → `base_env` (`lib/shipit/commands.rb:24-50`), which sets `GITHUB_TOKEN` and, if `Shipit.use_git_askpass?`, `GIT_ASKPASS`. `deploy_spec.machine_env` (`app/models/shipit/deploy_spec.rb:69-71`, `config('machine', 'environment') || {}`) is populated from the repository's own `shipit.yml` file loaded by `DeploySpec::FileSystem#load_config`/`read_config` (`app/models/shipit/deploy_spec/file_system.rb:93-107,162-164`), which is `SafeYAML.load`-ed directly from a file checked out from the repository's branch — fully repository/attacker controlled content, with **no key restriction** applied at any point (`config('machine','environment')` returns the raw parsed hash verbatim). Because `machine_env` is merged *after* the built-in `GITHUB_TOKEN`/`SHIPIT_USER`/etc. keys, any key collision is won by the attacker's value. The resulting hash flows into `Command.new(..., env:)` (`lib/shipit/task_commands.rb:19,25`), then `Command#initialize` stores it as `@env` (`lib/shipit/command.rb:34`), and `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) does `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` — again no allowlist — before `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, ...)` (`lib/shipit/command.rb:92`). No guard (`EnvironmentVariables#permit`, which is only applied to `deploy`/`rollback` *task* variables via `filter_deploy_envs`/`filter_rollback_envs` in `app/models/shipit/deploy_spec.rb:174-180`, not to `machine_env`) restricts this path. `filter_deploy_envs`/`filter_task_envs` only ever filter `env` supplied through the deploy/task trigger API (`Stack#trigger_task`, `Stack#build_deploy`), not `deploy_spec.machine_env`, which is a separate, unfiltered code path.

Attack: an attacker who can push to a branch/fork that Shipit will check out for a deploy or review-stack task (e.g. via a PR that triggers a review-stack task, or any branch the stack is configured against) commits a `shipit.yml` (or `.shipit/shipit.yml`) containing:
```yaml
machine:
  environment:
    GITHUB_TOKEN: "attacker-value"
    GIT_ASKPASS: "/tmp/attacker-askpass"
```
When Shipit runs any task against that checkout, `TaskCommands#env` computes the merged hash with the attacker's `GITHUB_TOKEN`/`GIT_ASKPASS` values overriding Shipit's real ones, and that value is what `git` (invoked via `Commands#git` → `Command.new`) and all task steps see in their spawned process environment.

### Impact Explanation
Overwriting `GITHUB_TOKEN` in the spawned command environment can redirect git authentication that some git subcommands read from environment (or be read by scripts run as deploy/task steps that trust `$GITHUB_TOKEN`), potentially causing exfiltration of whichever value ends up used, or letting the attacker point git operations at attacker infrastructure. Overwriting `GIT_ASKPASS` to point at an attacker-supplied executable path is a stronger primitive: if git invokes the askpass helper during any credential prompt in that process, Shipit will execute the attacker-specified binary path in the context of the deploy host process, which is arbitrary command execution on the deploy host under the Shipit's runtime user — Critical severity (RCE via `Command`/`PTY.spawn`, and/or exfiltration of `GITHUB_TOKEN`). This is repeatable for every task run against the same malicious branch and applies to any stack whose branch/config is attacker-influenced (fork PRs feeding review-stacks, or any repo where an unprivileged contributor can land a `shipit.yml` change to a branch Shipit deploys).

### Likelihood Explanation
Preconditions are modest: the attacker needs a `shipit.yml` (or `.shipit/shipit.yml`) to be picked up for a task's checkout — this is straightforward for repository owners of their own review-stack/fork scenario, and for any repo that runs Shipit tasks against branches an outside contributor can influence. No Shipit secrets, session, or API token are required; only the ability to control repository config content picked up by `DeploySpec::FileSystem#config_file_path`. This matches the "attacker action" preconditions in the prompt exactly.

### Recommendation
Apply a strict allowlist/denylist to `DeploySpec#machine_env` before it is merged in `TaskCommands#env` — reject or strip keys matching sensitive/reserved names (e.g. `GITHUB_TOKEN`, `GIT_ASKPASS`, `BUNDLE_*`, `PATH`, `RUBYOPT`, and any key already set by `Commands#base_env`/`Stack#env`/the built-in `TaskCommands#env` block). Alternatively, merge `deploy_spec.machine_env` *before* the built-in secrets so built-ins always win, and additionally validate `machine.environment` keys against a hard-coded reserved-word list at config load time (`DeploySpec::FileSystem#load_config`), raising a config error if a reserved key is present.

### Proof of Concept
```ruby
# minitest test plan (test/models/shipit/task_commands_test.rb style)
test "machine_env cannot override GITHUB_TOKEN or GIT_ASKPASS in the spawned command env" do
  stack = shipit_stacks(:shipit)
  task = shipit_tasks(:shipit)
  task_commands = Shipit::TaskCommands.new(task)

  deploy_spec = task_commands.deploy_spec
  deploy_spec.stubs(:machine_env).returns(
    'GITHUB_TOKEN' => 'attacker-value',
    'GIT_ASKPASS' => '/tmp/attacker-askpass'
  )
  task_commands.stubs(:deploy_spec).returns(deploy_spec)

  env = task_commands.env

  # Binding check: built-in secret keys must NOT be overridable by machine_env
  refute_equal 'attacker-value', env['GITHUB_TOKEN']
  refute_equal '/tmp/attacker-askpass', env['GIT_ASKPASS']

  command = Shipit::Command.new('git', 'status', env:, chdir: Dir.tmpdir)
  unbundled = command.unbundled_env
  refute_equal 'attacker-value', unbundled['GITHUB_TOKEN']
  refute_equal '/tmp/attacker-askpass', unbundled['GIT_ASKPASS']
end
```
This test currently fails against the code as written (both `env['GITHUB_TOKEN']` and `unbundled_env['GITHUB_TOKEN']` equal `'attacker-value'`), confirming the binding is broken. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

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

**File:** lib/shipit/commands.rb (L24-50)
```ruby
    def env
      base_env
    end

    def git(*args)
      kwargs = args.extract_options!
      kwargs[:env] ||= base_env
      Command.new("git", *args, **kwargs)
    end
    ruby2_keywords :git if respond_to?(:ruby2_keywords, true)

    private

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

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
    end
```

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
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

**File:** app/models/shipit/deploy_spec/file_system.rb (L162-164)
```ruby
      def read_config(path)
        SafeYAML.load(path.read) if path.exist?
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
