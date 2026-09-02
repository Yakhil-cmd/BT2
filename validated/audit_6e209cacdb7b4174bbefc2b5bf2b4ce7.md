### Title
Path traversal via `machine.directory` in shipit.yml escapes `working_directory` into an attacker-chosen filesystem path - ([File: lib/shipit/task_commands.rb])

### Summary
`DeploySpec#directory` (`config('machine', 'directory')`) is read verbatim from `shipit.yml` and joined with `@task.working_directory` in `TaskCommands#steps_directory` using `File.join`, with no sanitization for `..` segments. Because `shipit.yml` is checked out from the commit being deployed (including PR branches for ReviewStacks), a repository owner can supply `machine: {directory: '../../../../etc'}` and cause every deploy/task step `Command` to `chdir` and `mkdir_p` outside the sandboxed working directory tree.

### Finding Description
The broken binding is: `steps_directory == File.join(@task.working_directory, deploy_spec.directory)` is assumed to always resolve to a path **inside** `@task.working_directory`, but `File.join` performs no path-traversal normalization, so `deploy_spec.directory = '../../etc'` makes `steps_directory` resolve to a sibling/ancestor path such as `/data/deploys/<stack>/../../etc` → effectively `/etc` relative to the deploys root.

Code path:
- `TaskCommands#steps_directory` builds the chdir: [1](#0-0) 
- `deploy_spec.directory` reads directly from parsed YAML with no validation: [2](#0-1) 
- `steps_directory` is passed as `chdir:` for every deploy/install-dependencies command: [3](#0-2) 
- `Command#start` unconditionally creates the directory and spawns the process there: [4](#0-3) 

The `deploy_spec` is loaded from the checked-out working tree (`DeploySpec::FileSystem.new(@task.working_directory, @stack)`), which for review stacks is the fork/PR branch content — attacker-controlled once the ReviewStack is provisioned and a deploy/task runs against that commit. There is no schema/allow-list validation anywhere in `DeploySpec`, `DeploySpec::FileSystem`, or the YAML loading path that restricts `machine.directory` to a relative sub-path without `..`, and no `Pathname#cleanpath`/realpath containment check is performed before use as `chdir`.

None of the standard guards apply here: this is not a webhook/signature/authentication issue (`verify_signature`, `require_permission!`, etc. are irrelevant — the attacker's payload is delivered via the repository content itself, not HTTP params), and no repository/stack model validator constrains YAML `machine.directory` values.

### Impact Explanation
`FileUtils.mkdir_p(@chdir)` and `PTY.spawn(..., chdir: @chdir)` create a directory and execute shell commands (deploy/install-dependencies/checkout steps, though `checkout`/`clone` use `@task.working_directory` directly, not `steps_directory`) at attacker-controlled absolute-ish location outside the sandbox. Combined with attacker control over deploy/dependency step commands (`deploy_steps`, `dependencies_steps`, also from the same `shipit.yml`), the attacker already controls what commands run; the traversal additionally lets them choose *where* those commands run and where directories get created on the host filesystem, which can be leveraged to write/execute files outside the intended deploy sandbox (e.g., writing into shared paths, other stacks' working directories, or system directories the Shipit process user can access). This matches the Critical impact category: "RCE on the deploy host via `Command`/`PTY.spawn`" since the attacker gains execution-directory control that escapes the intended per-stack working-directory containment.

### Likelihood Explanation
Preconditions: the repository must have Shipit configured with review stacks enabled (or any stack whose `shipit.yml` is attacker-influenced — e.g., contributor with PR-merge or ReviewStack auto-provisioning on `opened`), and a deploy/task must run against the malicious commit. For a repo with review-stacks-on-open enabled, an unprivileged contributor opening a PR with a malicious `shipit.yml` is sufficient — no maintainer approval is required for the ReviewStack to provision and run steps, per `opened_active_stack?` in `LabelCapturingHandler`. This requires no secrets, no elevated GitHub role, and no privileged Shipit access — only the ability to push a branch/PR to a repo with Shipit configured against it. It is fully repeatable per PR/commit.

### Recommendation
Sanitize/validate `deploy_spec.directory` in `DeploySpec#directory` or `TaskCommands#steps_directory`: reject values containing `..` path segments or absolute paths, and additionally verify with `File.expand_path`/`Pathname#cleanpath` that the resolved path is still a descendant of `@task.working_directory` before use as `chdir` in `Command.new`.

### Proof of Concept
```ruby
# test/lib/shipit/task_commands_test.rb
test "steps_directory does not escape task.working_directory when deploy_spec.directory contains traversal" do
  task = shipit_deploys(:shipit_pending)
  commands = Shipit::TaskCommands.new(task)
  commands.stubs(:deploy_spec).returns(stub(directory: '../../etc', machine_env: {}))

  resolved = File.expand_path(commands.send(:steps_directory))
  expected_root = File.expand_path(task.working_directory)

  assert(
    resolved.start_with?(expected_root + File::SEPARATOR) || resolved == expected_root,
    "steps_directory (#{resolved}) escaped working_directory (#{expected_root})"
  )
end
```
This currently fails because `steps_directory` returns `File.join(task.working_directory, '../../etc')`, which resolves outside `task.working_directory`.

### Citations

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
