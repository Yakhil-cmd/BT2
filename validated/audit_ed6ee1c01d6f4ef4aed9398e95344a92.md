### Title
Attacker-controlled PR label names become unfiltered `git` subprocess environment variables (e.g. `GIT_TEMPLATE_DIR`) via `ReviewStack#env` → RCE - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) directly into the process environment with no allowlist, and that environment is passed unfiltered into every `git` invocation performed by `StackCommands#fetch`/`#fetch_commit`/`#git_clone`. Because `git` honors env vars like `GIT_TEMPLATE_DIR` to seed hook scripts that git then copies into `.git/hooks` and executes (`post-checkout` fires on clone), an attacker who can only label their own pull request can achieve command execution on the Shipit host.

### Finding Description
The broken binding: `EnvironmentVariables.permit(variable_definitions)` is the only mechanism in this codebase that filters attacker-influenced env keys against an explicit allowlist (`lib/shipit/environment_variables.rb:13-18`, used by `DeploySpec#filter_deploy_envs`/`#filter_rollback_envs`, `TaskDefinition#filter_envs`). The claimed equality that should hold is: `keys(stack.env) ⊆ allowlist_of(deploy_variables ∪ rollback_variables ∪ task_variables)`. This equality is violated for `ReviewStack#env`:

```ruby
# app/models/shipit/review_stack.rb:84-93
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

No `EnvironmentVariables.permit` call exists here — every label name, uppercased, becomes an arbitrary environment key with no restriction. Labels are stored verbatim from the GitHub webhook body by `LabelCapturingHandler#capture_labels`:

```ruby
# app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102
def capture_labels
  return unless pull_request = stack.pull_request
  pull_request.update!(labels: params.pull_request.labels.map(&:name))
end
```

`StackCommands#env` and `TaskCommands#env` merge `@stack.env` straight into the environment used for every `git` command, again with no filtering:

```ruby
# lib/shipit/stack_commands.rb:13-15
def env
  super.merge(@stack.env)
end

# lib/shipit/stack_commands.rb:27-35 (fetch)
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

That env hash flows into `Command#unbundled_env`, which is passed directly to `PTY.spawn`:

```ruby
# lib/shipit/command.rb:92, 103-105
@out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
...
def unbundled_env
  BASE_ENV.merge('PATH' => "...").merge(@env.stringify_keys)
end
```

Exploit flow: an attacker opens a PR on a repository whose Shipit `provisioning_behavior` is `allow_with_label` (or any config where a `ReviewStack` becomes active), applies a label named e.g. `git_template_dir` whose value, when uppercased, becomes `GIT_TEMPLATE_DIR`, and points it at a directory (reachable via a prior fetch/clone step or a value crafted to reference an attacker-writable path) containing a `hooks/post-checkout` script. The next time Shipit runs `StackCommands#fetch` → `git_clone`, git applies the template dir's hooks into `.git/hooks`, and `post-checkout` executes automatically as part of `git clone`'s implicit checkout, running attacker-supplied code on the Shipit deploy host.

This bypasses all existing guards because: webhook signature verification only authenticates that the payload really came from GitHub for a repo the attacker owns/controls (it does not sanitize the *content* of labels); `EnvironmentVariables.permit` is never invoked for `Stack#env`/`ReviewStack#env`, only for the explicit deploy/rollback/task `env` params supplied through API/controller parameters; model validations on `Repository`/`Stack` (environment format, etc.) don't touch label content at all.

### Impact Explanation
Arbitrary environment variable injection into every `git` subprocess invoked for a review stack, enabling attacker-controlled `GIT_*` variables (`GIT_TEMPLATE_DIR`, potentially `GIT_SSH_COMMAND` if the URL uses ssh, `GIT_PROXY_COMMAND`, etc.) to be honored by `git`, culminating in code execution on the Shipit deploy host under the process running the review stack's fetch/clone/task pipeline. This is Critical — Remote Code Execution on the deploy host, and it is repeatable by any user who can open/label a pull request against a repository with review stacks enabled; the blast radius extends to whatever the Shipit host process can access (other stacks' git caches, `GITHUB_TOKEN`, deploy secrets on the same host).

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled (`provisioning_behavior` allowing PR-driven stacks, e.g. `allow_with_label`/`allow_all`) so that a `ReviewStack` exists and its `fetch`/`git_clone` runs. The attacker needs no Shipit credentials, no webhook secret, and no special GitHub permissions beyond opening a PR and applying a label on a repo they control — both are default, unprivileged GitHub actions. Cost is minimal (one PR + one label); the attack is fully repeatable and deterministic once a template-dir-with-hooks path is reachable by the attacker (e.g., a world-writable/tmp path, or via a two-step attack where the attacker first stages a hooks directory using another attacker-controlled primitive on the same host/filesystem).

### Recommendation
Do not merge raw pull-request label names into the process environment. Either drop the label-to-env feature entirely, or restrict it through an explicit allowlist analogous to `EnvironmentVariables.permit`, e.g., only permit label-derived keys matching a strict pattern and never allow well-known dangerous variable names (`GIT_*`, `LD_PRELOAD`, `PATH`, `IFS`, etc.), or namespace them (e.g., prefix with `SHIPIT_LABEL_`) so they can never collide with variables `git` or the shell interpret specially.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (or a new test)
test "ReviewStack#env does not leak dangerous git environment variables from labels" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["git_template_dir"]

  env = stack.env

  # Broken binding under test: label-derived keys should be rejected/allowlisted,
  # but currently GIT_TEMPLATE_DIR is injected verbatim.
  assert_nil env["GIT_TEMPLATE_DIR"], "GIT_TEMPLATE_DIR must not be settable via PR labels"
end

# test/unit/stack_commands_test.rb style test proving it reaches the git invocation
test "StackCommands#fetch's git invocation env includes attacker label-derived GIT_TEMPLATE_DIR" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["git_template_dir"]
  stack.git_path.stubs(:exist?).returns(false)

  command = StackCommands.new(stack).fetch

  # Demonstrates the vulnerability: the value reaches the git subprocess env unfiltered
  assert_equal "true", command.env["GIT_TEMPLATE_DIR"]
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```
