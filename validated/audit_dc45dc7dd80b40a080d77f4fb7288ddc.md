Confirmed. `Stack#env` only sets fixed keys (`ENVIRONMENT`, `LAST_DEPLOYED_SHA`, `GITHUB_REPO_OWNER`, etc.) with no allowlist filtering mechanism applied to `ReviewStack#env`'s label merge, and `StackCommands#fetch` passes this env straight to `Command`, whose `unbundled_env` merges `@env.stringify_keys` directly into the subprocess environment for `PTY.spawn`.### Title
Unfiltered pull-request label names inject `GIT_SSH_COMMAND` into `git fetch`/`git clone` subprocess environment - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) directly into the stack environment hash with no allowlist, and `LabelCapturingHandler#capture_labels` persists label names verbatim from the webhook payload. `StackCommands#fetch`/`fetch_commit` pass this unfiltered env straight into `Command`, whose `unbundled_env` merges it into the process environment handed to `PTY.spawn`, letting a fork PR author set `GIT_SSH_COMMAND` and get it inherited by the `git fetch origin`/`git clone` subprocess on the deploy host.

### Finding Description
The broken binding is: the set of environment variables passed to the `git` subprocess for a `ReviewStack` should equal `Stack#env` (a fixed set: `ENVIRONMENT`, `LAST_DEPLOYED_SHA`, `GITHUB_REPO_OWNER`, `GITHUB_REPO_NAME`, `DEPLOY_URL`, `BRANCH`) plus `Commands#base_env` (`Shipit.env`, `GITHUB_DOMAIN`, `GITHUB_TOKEN`), but it instead equals that set **union** an attacker-controlled set `{label.upcase => "true" for label in pull_request.labels}` with no key allowlist: [1](#0-0) 

The path: an unprivileged fork-PR author opens a PR against a repository that has review stacks enabled and adds a label with a literal name such as `git_ssh_command`. GitHub sends a `pull_request` webhook (`opened`/`labeled`/`unlabeled`/`reopened`). `LabelCapturingHandler#capture_labels` writes `params.pull_request.labels.map(&:name)` straight into `pull_request.labels` for any active (non-archived) stack, with no character/name filtering beyond the `ExplicitParameters` schema requiring `name` be a `String`: [2](#0-1) 

Under `prevent_with_label`, the stack is only archived while the *specific configured provisioning label* is present; any other label (like the attacker's `git_ssh_command`) does not archive the stack and is still captured, since `labeled_active_stack?`/`opened_active_stack?` only check `stack.present? && !stack.archived?`: [3](#0-2) 

When any git operation subsequently runs for that stack (e.g. `StackCommands#fetch`, `fetch_commit`, or via `TaskCommands`/`DeployCommands` which delegate to it), `env` is computed as `super.merge(@stack.env)`, i.e. `Commands#base_env` merged with the poisoned `ReviewStack#env`: [4](#0-3) 

`Command#initialize` stores this hash verbatim (only stringifying values), and `Command#unbundled_env` merges it directly into the child process environment passed to `PTY.spawn`: [5](#0-4) [6](#0-5) 

Existing guards do not stop this: `EnvironmentVariables#permit`, the allowlist mechanism used elsewhere for user-supplied env (`DeploySpec#filter_deploy_envs`, `TaskDefinition#filter_envs`, exercised in `EnvironmentVariablesTest` and the API controllers), is never invoked on `Stack#env`/`ReviewStack#env` before it reaches `StackCommands`/`TaskCommands`/`DeployCommands`. The `params` schema for the label-capturing/labeled/unlabeled handlers only validates `labels[].name` as a `String` — it does not restrict characters, length, or reserved names. `verify_signature`/webhook signature checks only gate whether the *request* is accepted, not what a label name may contain once it is a legitimate PR event on a repo the attacker owns/forked.

### Impact Explanation
Any fork/PR author with write access to their own fork (no Shipit session, token, or team membership needed) can cause the Shipit deploy host to spawn `git fetch`/`git clone` with an attacker-chosen `GIT_SSH_COMMAND`. Git invokes `GIT_SSH_COMMAND` as the program used for any ssh-transport operation performed by that git process (including submodule or remote-helper operations under the same environment), giving the attacker execution of an arbitrary command on the deploy host under the Shipit process's privileges — Remote Code Execution on the deploy host. This is repeatable on every `fetch`/`fetch_commit`/`clone` call for the affected review stack, and the same primitive (arbitrary env-var injection with no allowlist) taints every downstream `TaskCommands`/`DeployCommands` invocation for that stack (`env` merges `@stack.env` in each), so it is not limited to a single command. Blast radius is scoped to review-stack-enabled repositories (the specific repo/fork opening the PR), matching Critical — RCE on the deploy host via `Command`/`PTY.spawn`.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled (`review_stacks_enabled`) with any `provisioning_behavior` (including `prevent_with_label`, as long as the attacker avoids using the specific provisioning label so the stack stays active). Attacker cost is trivial — open a PR from a fork and add a label named `git_ssh_command` (GitHub allows arbitrary label names on any label the PR author can create/apply to their own PR, or an existing repo label can be reused). No secrets, tokens, or elevated GitHub roles are required. This is easily repeatable against any repository with review stacks enabled.

### Recommendation
Do not merge raw pull-request label names into the process environment un-filtered. Either (a) drop the label-to-env feature entirely, (b) route `ReviewStack#env`'s label-derived hash through `EnvironmentVariables#permit` against an explicit allowlist of permitted label-derived variable names configured per-repository (mirroring `DeploySpec#filter_deploy_envs`/`TaskDefinition#filter_envs`), or (c) at minimum reject/strip label names that collide with sensitive/reserved environment variable names (`GIT_SSH_COMMAND`, `GIT_ASKPASS`, `PATH`, `GITHUB_TOKEN`, `LD_PRELOAD`, etc.) before they are persisted or merged into `env`.

### Proof of Concept
minitest plan (`test/lib/shipit/stack_commands_test.rb` or extending `test/lib/shipit/task_commands_test.rb`):
```ruby
test "prevent_with_label: PR label sets GIT_SSH_COMMAND used by StackCommands#fetch" do
  stack = shipit_stacks(:review_stack)
  repository = stack.repository
  repository.provisioning_behavior = :prevent_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  # Attacker-controlled label, distinct from the configured provisioning label
  stack.pull_request.labels = ["git_ssh_command"]

  command = Shipit::StackCommands.new(stack).fetch

  # Binding under test: env passed to git fetch should equal Stack#env ∪ base_env only
  refute_includes stack.env.keys, "GIT_SSH_COMMAND" # expected (should hold, does not)
  assert_equal "true", command.env["GIT_SSH_COMMAND"] # actual (demonstrates the leak)
end
```
This proves `GIT_SSH_COMMAND` (derived from an unprivileged fork PR's label, uppercased) reaches the `Command` object backing `git fetch origin` under `prevent_with_label`, with no live GitHub call required.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L62-72)
```ruby
          def labeled_active_stack?
            labeled? && stack.present? && !stack.archived?
          end

          def unlabeled_active_stack?
            unlabeled? && stack.present? && !stack.archived?
          end

          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
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

**File:** lib/shipit/command.rb (L92-105)
```ruby
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
