### Title
Path traversal in `machine.directory` allows a stack's `shipit.yml` to `chdir`/execute commands outside its own working directory - (File: lib/shipit/task_commands.rb)

### Summary
`TaskCommands#steps_directory` builds the `chdir` for every deploy/rollback/task `Command` by joining `@task.working_directory` with the unsanitized `machine.directory` value from the repository's own `shipit.yml`. Because `File.join` performs no normalization and no bounds check is applied afterward, a value like `../../other-stack-slug/environment/deploys/<id>` (or any `../`-laden string) escapes `@task.working_directory` and points into a sibling task/stack directory under `Shipit.root.join('data','stacks', ...)`.

### Finding Description
The claimed binding is: `steps_directory == File.join(@task.working_directory, deploy_spec.directory)` must always resolve to a path *inside* `@task.working_directory`. Tracing the code:

- `deploy_spec.directory` is `config('machine', 'directory')`, sourced straight from the parsed `shipit.yml` in the repository being deployed, with no path validation. [1](#0-0) 
- `TaskCommands#steps_directory` does:
```ruby
def steps_directory
  if sub_directory = deploy_spec.directory.presence
    File.join(@task.working_directory, sub_directory)
  else
    @task.working_directory
  end
end
``` [2](#0-1) 
`File.join` does not collapse `..` segments in any bounds-restrictive way — it just string-concatenates and inserts one `/`, so `File.join('/data/stacks/a/production/deploys/5', '../../../b/production/deploys/5')` literally yields a path that walks up out of `.../a/production/deploys/5` into `.../b/production/deploys/5`.
- This value is used verbatim as `chdir:` for every `Command.new` in `#install_dependencies` and `#perform`. [3](#0-2) 
- `Command#start` then does `FileUtils.mkdir_p(@chdir)` (creating the traversal target if missing) and passes it directly as the `chdir:` option to `PTY.spawn`. [4](#0-3) 
- `@task.working_directory` is `File.join(stack.deploys_path, id.to_s)`, and `stack.deploys_path` is `Rails.root.join('data','stacks', repo_owner, repo_name, environment, 'deploys')`. [5](#0-4) [6](#0-5) 

All stacks/tasks share the common ancestor `Rails.root.join('data','stacks')`, so with enough `../` segments an attacker-controlled `machine.directory` can reach any other stack's task checkout, or arbitrary paths on the host filesystem (limited only by permissions of the shipit process).

Existing guards do not intercept this: `steps_directory` performs no `Pathname#expand_path` + prefix check, no `File.absolute_path` normalization, and no rejection of `..` segments. The deploy-spec merge/cacheable logic (`app/models/shipit/deploy_spec/file_system.rb`) also passes `directory` through unmodified into the cached spec. [7](#0-6) 

Attacker flow: an attacker who controls (or forks/PRs into, depending on repo access-control config) a repository onboarded to Shipit sets, in `shipit.yml`:
```yaml
machine:
  directory: ../../other-org/other-repo/production/deploys/999999999
```
When their own stack's deploy/task runs, `steps_directory` resolves outside their own `working_directory` tree. Because `FileUtils.mkdir_p` will happily create any missing intermediate directories the shipit process has permission to create, this also allows creating/writing to arbitrary sibling paths, not just existing ones — and if the resolved path lands inside another real stack's active/former working directory, the attacker's deploy/rollback commands execute chdir'd into (and can corrupt/exfiltrate) that other stack's checkout.

### Impact Explanation
This matches the Critical category "a payload for one repository mutating another's stack ... or an unauthorized deploy": an attacker's own `shipit.yml`, which they fully control via a PR/push to their own fork or a repository they administer, causes shell commands (`PTY.spawn`) to execute with `chdir` inside a different stack's working directory tree, or to fabricate directories anywhere the shipit process can write. Concretely this can:
- Corrupt or read files from another tenant's active task checkout if it runs concurrently (deploys for different stacks execute in parallel across the host).
- Escalate to writing/reading files elsewhere on the host filesystem under the `data/stacks` tree or beyond, depending on how far `../` traversal is chained relative to the filesystem root permissions of the shipit worker.
This is a cross-tenant blast radius: any onboarded repository is a potential attacker against any other onboarded repository sharing the same Shipit host.

### Likelihood Explanation
Preconditions are minimal: the attacker needs a Shipit-managed repository (or the ability to modify `shipit.yml` on a branch that gets deployed — e.g. by pushing to their own fork/branch if the stack config permits deploying arbitrary branches, or by having merge/push rights to their own onboarded stack). No Shipit session, API token, or GitHub secret is required — only the ability to control the YAML file content that becomes `deploy_spec.directory`, which is standard onboarding functionality (`machine.directory` is a documented, supported key). The attacker needs to know or guess the target sibling directory path (stack slug/environment/task-id), which is discoverable since stack URLs (`repo_owner/repo_name/environment`) and task ids are visible in the Shipit UI/API for any stack the attacker can see, or brute-forceable for sequential task ids.

### Recommendation
In `TaskCommands#steps_directory`, resolve and validate the joined path stays within `@task.working_directory`:
```ruby
def steps_directory
  return @task.working_directory unless (sub_directory = deploy_spec.directory.presence)

  base = Pathname.new(@task.working_directory).expand_path
  resolved = base.join(sub_directory).expand_path

  unless resolved.to_s == base.to_s || resolved.to_s.start_with?("#{base}/")
    raise Shipit::DeploySpec::InvalidSubdirectory, "machine.directory must stay within the working directory"
  end

  resolved.to_s
end
```
Additionally consider rejecting absolute paths and `..` segments outright in `DeploySpec#directory` at parse time for defense in depth.

### Proof of Concept
```ruby
# test/unit/task_commands_test.rb (or deploy_commands_test.rb)
test "#steps_directory does not escape the task working directory via machine.directory traversal" do
  deploy_spec = stub(directory: '../../other-repo/production/deploys/1', machine_env: {})
  @commands.stubs(:deploy_spec).returns(deploy_spec)

  working_directory = Pathname.new(@task.working_directory).expand_path
  resolved = Pathname.new(@commands.send(:steps_directory)).expand_path

  # Binding under test: resolved path must stay confined within working_directory
  assert(
    resolved.to_s == working_directory.to_s || resolved.to_s.start_with?("#{working_directory}/"),
    "steps_directory escaped the task's working_directory: #{resolved} is outside #{working_directory}"
  )
end
```
Running this against the current implementation fails because `File.join(@task.working_directory, '../../other-repo/production/deploys/1')` resolves outside `@task.working_directory`, confirming the traversal.

### Citations

**File:** app/models/shipit/deploy_spec.rb (L73-75)
```ruby
    def directory
      config('machine', 'directory')
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

**File:** app/models/shipit/task.rb (L373-375)
```ruby
    def working_directory
      File.join(stack.deploys_path, id.to_s)
    end
```

**File:** app/models/shipit/stack.rb (L395-401)
```ruby
    def base_path
      @base_path ||= Rails.root.join('data', 'stacks', repo_owner, repo_name, environment)
    end

    def deploys_path
      @deploys_path ||= base_path.join("deploys")
    end
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L55-59)
```ruby
          'machine' => {
            'environment' => discover_machine_env.merge(machine_env),
            'directory' => directory,
            'cleanup' => true
          },
```
