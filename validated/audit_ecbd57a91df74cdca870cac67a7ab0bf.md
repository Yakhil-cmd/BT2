Based on the investigation, the vulnerability is confirmed as reachable and unmitigated.

### Title
Fork-controlled `machine.environment` in `shipit.yml` injects arbitrary environment variables (e.g. `LD_PRELOAD`) into `TaskCommands#install_dependencies` process env, enabling RCE on the deploy host - ([File: lib/shipit/task_commands.rb, app/models/shipit/deploy_spec.rb, lib/shipit/command.rb])

### Summary
`DeploySpec#machine_env` returns the `machine.environment` section of `shipit.yml` verbatim, and `TaskCommands#env` merges it unfiltered into the environment passed to every `Command`, including the `bundle`/`ruby` dependency-install step. For a repository with `provisioning_behavior = allow_all`, the review stack checks out the fork PR's commit and reads its `shipit.yml`, so the PR author fully controls this environment hash, including loader variables like `LD_PRELOAD`.

### Finding Description
The broken invariant is: `TaskCommands#env == Shipit-controlled base env + stack env + task env + machine_env + task-specific overrides`, where `machine_env` should be immutable and Shipit-controlled. Instead, `machine_env` is read from the fork branch's `shipit.yml` and merged unfiltered.

**Code path:**
1. Attacker opens PR on fork with malicious `shipit.yml` containing `machine.environment.LD_PRELOAD=/path/to/attacker.so`
2. Repository has `provisioning_behavior = allow_all` (enabled in settings)
3. GitHub webhook triggers `PullRequest::OpenedHandler` → `ReviewStackAdapter.find_or_create!` → creates `ReviewStack` with `branch = pull_request.head.ref` (fork branch)
4. `PerformTaskJob` executes task on review stack
5. `TaskCommands.new(task)` → `deploy_spec = DeploySpec::FileSystem.new(@task.working_directory, @stack)` reads `shipit.yml` from the fork branch's working directory
6. `install_dependencies` calls `Command.new(command_line, env:, chdir: steps_directory)` where `env = TaskCommands#env`
7. `TaskCommands#env` (line 33–48 in task_commands.rb) merges:
   - `super` (Commands#env base)
   - `@stack.env` (stack-level env)
   - Shipit-controlled vars (SHIPIT_USER, EMAIL, BUNDLE_PATH, etc.)
   - **`deploy_spec.machine_env`** (line 46) ← **unfiltered fork-controlled**
   - `@task.env` (task-level env)
8. `deploy_spec.machine_env` (line 69–71 in deploy_spec.rb) returns `config('machine', 'environment') || {}` — the raw YAML value
9. `DeploySpec::FileSystem#cacheable_config` (line 56 in deploy_spec/file_system.rb) merges `discover_machine_env.merge(machine_env)` into the config, but `discover_machine_env` is empty by default (line 292–294 in deploy_spec.rb)
10. `Command#start` (line 92 in command.rb) calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` where `unbundled_env = BASE_ENV.merge(...).merge(@env.stringify_keys)` (line 104)
11. Ruby's `PTY.spawn` and the ruby toolchain honour `LD_PRELOAD` in the inherited environment, preloading the attacker's shared object into every spawned process

**Root cause:** No validation or filtering of `machine.environment` keys. The code assumes the fork branch's `shipit.yml` is trusted, but in `allow_all` mode, any GitHub user can push a PR with arbitrary YAML.

**Attacker's exact request:**
- Push commit to fork with `shipit.yml`:
  ```yaml
  machine:
    environment:
      LD_PRELOAD: /tmp/attacker.so
  dependencies:
    override:
      - bundle install
  ```
- Open PR on main repo with `provisioning_behavior = allow_all`
- GitHub webhook auto-creates review stack, checks out fork branch
- Task execution runs `bundle install` with `LD_PRELOAD` in env
- Attacker's `.so` is preloaded into the ruby process and all child processes

**Why existing guards fail:**
- `EnvironmentVariables#permit` (lib/shipit/environment_variables.rb) is only used for task-level `deploy_variables` (user-facing task inputs), not for `machine.environment`
- No validation on `DeploySpec#machine_env` keys
- No filtering in `TaskCommands#env` merge chain
- `ReviewStack#env` (app/models/shipit/review_stack.rb, line 84–93) only adds PR labels as env vars; it does not sanitize `machine_env`

### Impact Explanation
**What is executed:** Every process spawned by the deploy task (ruby, bundle, git, shell commands) runs with the attacker's preloaded shared object, granting arbitrary code execution in the deploy host's context.

**Which repository or party:** The attacker's fork of any repository with `provisioning_behavior = allow_all` and review stacks enabled. The exploit runs on the Shipit deploy host under the Shipit process user (typically unprivileged but with access to deploy credentials, GitHub tokens, and deploy output).

**Repeatability:** Per-request. Every PR opened on the fork with a malicious `shipit.yml` triggers a new review stack and task execution.

**Blast radius:** Single repository per exploit, but across all review stacks for that repository. If the host app runs multiple repositories on the same Shipit instance, the attacker gains RCE on the shared deploy host.

**Matching severity:** Critical — Remote Code Execution on the Shipit deploy host via `Command#start` → `PTY.spawn`, matching the HackerOne/Immunefi RCE class.

### Likelihood Explanation
**Preconditions:**
- Repository has `review_stacks_enabled = true` and `provisioning_behavior = allow_all`
- Attacker can push to a fork and open a PR (any GitHub user)

**Shipit and repository configuration:** Default review stack settings enable `allow_all` as documented (README.md line 19, docs/review_stacks.md line 19)

**Attacker cost:** Minimal — write a `shipit.yml` with `LD_PRELOAD`, compile a trivial `.so` (or use an existing one), push to fork, open PR

**Feasibility:** High — the code path is direct and unguarded

**Repeatability:** Unlimited per repository

### Recommendation
Whitelist allowed keys in `machine.environment` to exclude loader variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, etc.) and other security-sensitive variables. Alternatively, sanitize `machine_env` in `TaskCommands#env` using `EnvironmentVariables#permit` with a schema of allowed keys, or filter the merged env before passing to `Command`.

**Specific fix:**
In `lib/shipit/task_commands.rb`, line 46, replace:
```ruby
.merge(deploy_spec.machine_env)
```
with:
```ruby
.merge(sanitize_machine_env(deploy_spec.machine_env))
```

And add:
```ruby
private

def sanitize_machine_env(env)
  # Reject loader and security-sensitive variables
  BLOCKED_ENV_KEYS = %w[LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_FORCE_FLAT_NAMESPACE].freeze
  env.reject { |k, _| BLOCKED_ENV_KEYS.include?(k) }
end
```

Or, more robustly, define an allowlist of safe keys in the deploy spec schema and validate against it.

### Proof of Concept
```ruby
# test/lib/shipit/task_commands_test.rb

test "machine.environment LD_PRELOAD is blocked from reaching install_dependencies" do
  stack = shipit_stacks(:review_stack)
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  # Simulate fork branch's shipit.yml with malicious LD_PRELOAD
  deploy_spec = mock('deploy_spec')
  deploy_spec.stubs(:machine_env).returns({ 'LD_PRELOAD' => '/tmp/attacker.so' })
  deploy_spec.stubs(:dependencies_steps!).returns(['bundle install'])
  deploy_spec.stubs(:directory).returns(nil)

  commands = Shipit::TaskCommands.new(task)
  commands.stubs(:deploy_spec).returns(deploy_spec)

  # Assert LD_PRELOAD does NOT reach the command env
  install_cmds = commands.install_dependencies
  assert_equal 1, install_cmds.length
  assert_nil install_cmds.first.env['LD_PRELOAD'], "LD_PRELOAD should be filtered from env"
end

test "machine.environment LD_PRELOAD reaches install_dependencies (vulnerability)" do
  stack = shipit_stacks(:review_stack)
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  # Simulate fork branch's shipit.yml with malicious LD_PRELOAD
  deploy_spec = mock('deploy_spec')
  deploy_spec.stubs(:machine_env).returns({ 'LD_PRELOAD' => '/tmp/attacker.so' })
  deploy_spec.stubs(:dependencies_steps!).returns(['bundle install'])
  deploy_spec.stubs(:directory).returns(nil)

  commands = Shipit::TaskCommands.new(task)
  commands.stubs(:deploy_spec).returns(deploy_spec)

  # BEFORE FIX: LD_PRELOAD reaches the command env (vulnerability)
  install_cmds = commands.install_dependencies
  assert_equal 1, install_cmds.length
  assert_equal '/tmp/attacker.so', install_cmds.first.env['LD_PRELOAD'], "LD_PRELOAD is currently unfiltered"
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
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

**File:** app/models/shipit/review_stack.rb (L1-50)
```ruby
# frozen_string_literal: true

module Shipit
  class ReviewStack < Shipit::Stack
    def self.clear_stale_caches
      Shipit::ReviewStack.where(
        "archived_since > :earliest AND archived_since < :latest",
        earliest: 1.day.ago,
        latest: 1.hour.ago
      ).find_each do |review_stack|
        review_stack.clear_local_files
      end
    end

    def self.delete_old_deployment_directories
      Shipit::Deploy.not_active.where(
        "created_at > :earliest AND updated_at < :latest",
        earliest: 1.day.ago,
        latest: 1.hour.ago
      ).find_each do |deploy|
        Shipit::Commands.for(deploy).clear_working_directory
      end
    end

    def update_latest_deployed_ref
      # noop: last deployed ref is useless for review stacks
    end

    model_name.class_eval do
      def route_key
        "stacks"
      end

      def singular_route_key
        "stack"
      end
    end

    has_one :pull_request, foreign_key: :stack_id

    after_commit :emit_added_hooks, on: :create
    after_commit :emit_updated_hooks, on: :update
    after_commit :emit_removed_hooks, on: :destroy

    state_machine :provision_status, initial: :deprovisioned do
      state :provisioned
      state :provisioning
      state :deprovisioning
      state :deprovisioned

```
