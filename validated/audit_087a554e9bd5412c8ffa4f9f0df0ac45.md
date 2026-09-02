Confirmed. The trace is: `Command#start` calls `FileUtils.mkdir_p(@chdir)` then `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` with no sanitization of `@chdir` beyond `.to_s`. [1](#0-0) 

`TaskCommands#steps_directory` builds `@chdir` by `File.join(@task.working_directory, sub_directory)` where `sub_directory = deploy_spec.directory.presence`, and `deploy_spec.directory` returns `config('machine', 'directory')` verbatim from the parsed `shipit.yml` with no path validation. [2](#0-1) [3](#0-2) 

`DeploySpec::FileSystem#file` demonstrates the same unguarded join pattern for `directory`, and this behavior is even explicitly documented/tested as intended: `machine.directory` is meant to let repos point deploy scripts at any subfolder, with a test confirming `File.join(@app_dir, subdir, 'baz')` for an absolute-looking subdir like `/foo/bar`. [4](#0-3) [5](#0-4) [6](#0-5) 

The deploy spec, including `directory`, is cached from the checked-out fork/PR branch via `CacheDeploySpecJob#perform`, which builds `DeploySpec::FileSystem.new(path, stack)` from the temporary working directory checked out for the review-stack's commit, and this whole flow is gated behind `OpenedHandler#provision?` requiring `repository.provisioning_behavior_allow_all?` (or a label), matching the stated precondition. [7](#0-6) [8](#0-7) 

Nowhere in this chain — `DeploySpec#directory`, `DeploySpec::FileSystem#file`, `TaskCommands#steps_directory`, or `Command#initialize`/`#start` — is `..`, an absolute path, or any traversal sequence rejected or normalized before it becomes `@chdir` passed to `FileUtils.mkdir_p` and `PTY.spawn`. This confirms the binding is broken exactly as the question states: the `chdir` value can escape `@task.working_directory`/`@stack.base_path` based purely on attacker-controlled `.shipit/shipit.yml` content, once the repository owner (who is a legitimate, though possibly separate, party) has enabled `provisioning_behavior_allow_all` (or a label-based mode the PR author can satisfy by self-labeling, depending on config) for review stacks.

### Title
Unsanitized `machine.directory` from attacker PR's `shipit.yml` enables path traversal into `Command#chdir` / `PTY.spawn` working directory - (File: `lib/shipit/task_commands.rb`, `app/models/shipit/deploy_spec.rb`, `lib/shipit/command.rb`)

### Summary
`TaskCommands#steps_directory` joins the attacker-controlled `machine.directory` value from a PR's `.shipit/shipit.yml` onto `@task.working_directory` with a plain `File.join`, and this becomes the `chdir:` argument passed straight through to `FileUtils.mkdir_p` and `PTY.spawn` in `Command#start` with no traversal or absolute-path check anywhere in the chain. Any PR author whose repository has review stacks enabled with `provisioning_behavior_allow_all` (or satisfies the label-based policy) can set `machine: {directory: '../../../../tmp'}` to force all deploy/review task steps to execute with an arbitrary host working directory.

### Finding Description
The broken binding: the question's claimed invariant is `chdir == @stack.base_path/@task.working_directory/<safe-subpath>`; in reality `chdir == File.join(@task.working_directory, attacker_controlled_string)` with no confinement check, so for `attacker_controlled_string = '../../../../tmp'` the two diverge — `chdir` resolves entirely outside the stack's working directory tree.

Path: `OpenedHandler#process` (gated by `provision?`) creates a review stack for the attacker's fork/branch [9](#0-8) . `CacheDeploySpecJob#perform` checks out that branch into a temporary directory and builds `DeploySpec::FileSystem.new(path, stack)`, caching it onto the stack [7](#0-6) . `DeploySpec#directory` reads `config('machine', 'directory')` straight from the parsed YAML with no validation [3](#0-2) . When a task runs, `TaskCommands#steps_directory` does `File.join(@task.working_directory, sub_directory)` [2](#0-1) , and this value is passed as `chdir:` into `Command.new(...)` for every deploy/rollback/task step [10](#0-9) . `Command#start` then does `FileUtils.mkdir_p(@chdir)` followed by `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` with `@chdir = chdir.to_s`, again with no sanitization [1](#0-0) .

Root cause: `machine.directory` is designed to point at a subfolder within the checked-out repo (per README: "specifies a subfolder in which to execute all tasks") [6](#0-5) , but no code confines the resulting path to be a descendant of `@task.working_directory`. This is also demonstrated by the existing test asserting `File.join(@app_dir, subdir, 'baz')` for an arbitrary `subdir` value, with no rejection of traversal-style strings [5](#0-4) .

Existing guards checked: `provisioning_behavior_allow_all?`/label checks only gate whether a review stack is provisioned at all, not the content of `shipit.yml` [8](#0-7) ; there is no `Stack`/`Repository` model validation on `machine.directory`, and `DeploySpec::FileSystem#file`/`#config_file_path` only govern where the `shipit.yml` file itself is read from, not where later task commands execute.

### Impact Explanation
Every deploy, rollback, review-stack, and custom task step for the stack executes via `PTY.spawn` with `chdir` pointed at an attacker-chosen filesystem path (e.g. `/tmp`, or any writable/traversable path reachable from the deploy host's filesystem permissions), and `FileUtils.mkdir_p` will create that directory tree if absent. Combined with attacker-controlled step commands (also from `shipit.yml`/task definitions), this is arbitrary command execution with an attacker-chosen working directory on the deploy host — Critical RCE/arbitrary filesystem write, scoped to whichever repository/stack the attacker's PR targets, and repeatable on every task run for that PR/review stack.

### Likelihood Explanation
Requires `repository.review_stacks_enabled` plus `provisioning_behavior_allow_all` (or attacker satisfying the label policy) as stated in the preconditions — this is a repository-owner configuration choice, not a Shipit operator secret or privileged credential. Given that configuration, the attack cost is a single PR with a `.shipit/shipit.yml` containing `machine: {directory: '...'}`; no authentication, tokens, or webhook secrets are needed beyond the normal GitHub webhook flow already trusted for review-stack creation.

### Recommendation
In `TaskCommands#steps_directory` (and/or `DeploySpec::FileSystem#file`), resolve the joined path and assert it remains a descendant of `@task.working_directory`/`@stack.base_path` (e.g., via `Pathname#expand_path` and a prefix check), rejecting or clamping any `machine.directory` value that traverses outside that root before it is ever used to build `chdir`.

### Proof of Concept
minitest plan (`test/unit/task_commands_test.rb` or similar, no live GitHub):
1. Build a `stack` fixture and a `TaskCommands` (or `DeployCommands`) instance for a `task` whose `working_directory` is a known path, e.g. `/data/shipit/stack/deploys/123`.
2. Stub `deploy_spec.directory` to return `'../../../../tmp'`.
3. Assert the binding before/after: 
   - Expected (claimed) invariant: `Pathname.new(commands.send(:steps_directory)).expand_path.to_s.start_with?(task.working_directory)` should be `true`.
   - Actual: `commands.send(:steps_directory)` equals `File.join(task.working_directory, '../../../../tmp')`, and `Pathname.new(...).expand_path.to_s` resolves to `/tmp`, which does **not** start with `task.working_directory` — assert this mismatch (`refute path.start_with?(task.working_directory)`).
4. Optionally instantiate `Command.new('true', chdir: commands.send(:steps_directory), env: {})` and assert `command.chdir` equals the traversed, out-of-root path, confirming it would reach `FileUtils.mkdir_p`/`PTY.spawn` unmodified.

### Citations

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

**File:** app/models/shipit/deploy_spec.rb (L73-75)
```ruby
    def directory
      config('machine', 'directory')
    end
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L27-33)
```ruby
      def file(path, root: false)
        if root || directory.blank?
          @app_dir.join(path)
        else
          Pathname.new(File.join(@app_dir, directory, path))
        end
      end
```

**File:** test/models/deploy_spec_test.rb (L719-724)
```ruby
    test "#file is impacted by `machine.directory`" do
      subdir = '/foo/bar'
      @spec.stubs(:load_config).returns('machine' => { 'directory' => subdir })
      assert_instance_of Pathname, @spec.file('baz')
      assert_equal File.join(@app_dir, subdir, 'baz'), @spec.file('baz').to_s
    end
```

**File:** README.md (L424-432)
```markdown
<h3 id="directory">Directory</h3>

**<code>machine.directory</code>** specifies a subfolder in which to execute all tasks. Useful for repositories containing multiple applications or if you don't want your deploy scripts to be located at the root.

For example:
```yml
machine:
  directory: scripts/deploy/
```
```

**File:** app/jobs/shipit/cache_deploy_spec_job.rb (L16-23)
```ruby
    def perform(stack)
      return if stack.inaccessible?

      commit = stack.commits.reachable.last
      commands = Commands.for(stack)
      commands.with_temporary_working_directory(commit:, recursive: false) do |path|
        stack.update!(cached_deploy_spec: DeploySpec::FileSystem.new(path, stack))
      end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-70)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def pull_request
            params.pull_request
          end

          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
