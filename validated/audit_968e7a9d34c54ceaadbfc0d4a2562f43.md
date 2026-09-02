### Title
Unfiltered PR-label-derived env reaches `git fetch`/`git clone` in `StackCommands#fetch`, allowing `GIT_TEMPLATE_DIR` injection - (File: `lib/shipit/stack_commands.rb`)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) directly into the stack's environment hash with no allowlist, and `StackCommands#fetch`/`fetch_commit`/`fetch_deployed_revision` pass that env straight to `Command`/`PTY.spawn` without ever calling `EnvironmentVariables#permit`. This lets a PR label named `git_template_dir` become `ENV['GIT_TEMPLATE_DIR']` for the `git clone`/`git fetch` calls that provision/refresh a review stack's git cache, whereas the `deploy`/`rollback`/`task` paths are protected by `filter_deploy_envs`/`filter_rollback_envs`/`filter_task_envs`.

### Finding Description
The broken binding: the set of env keys that reach `PTY.spawn` for the `fetch` step should equal the whitelist defined by `deploy_variables`/`rollback_variables` (i.e. `env_reaching_spawn ⊆ allowed_variable_names`), but for `fetch` it instead equals `env_reaching_spawn == StackCommands#env == super.merge(@stack.env)`, i.e. unrestricted.

Path:
1. `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim from the webhook payload onto `pull_request.labels` [1](#0-0) . Labels are attacker-named strings coming straight from the PR's `labels` array in the webhook body, with only a `String` type schema check [2](#0-1) .
2. `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into the stack env with no key allowlist [3](#0-2) . A label literally named `git_template_dir` becomes `{"GIT_TEMPLATE_DIR" => "true"}`.
3. `StackCommands#env` merges `@stack.env` (which for a `ReviewStack` includes the label-derived keys) on top of the base git env [4](#0-3) .
4. `StackCommands#fetch`, `#fetch_commit`, and `#fetch_deployed_revision` pass this `env` unfiltered directly to `git(...)`/`Command.new(...)` [5](#0-4) [6](#0-5) .
5. `Command#start` spawns the process with `unbundled_env` = `BASE_ENV.merge(...).merge(@env.stringify_keys)`, with no key filtering at all [7](#0-6) .

Root cause: unlike `Stack#build_deploy`, which explicitly sanitizes env via `filter_deploy_envs(env.to_h)` → `EnvironmentVariables.with(env).permit(deploy_variables)` [8](#0-7) [9](#0-8) , and `EnvironmentVariables#permit` raises `NotPermitted` for any key not in the whitelist [10](#0-9) , the `fetch`/`fetch_commit`/`fetch_deployed_revision`/`fetched?` methods in `StackCommands` never call `permit` — they use the raw merged `env` unconditionally.

`GIT_TEMPLATE_DIR` is a standard git environment variable that causes `git clone`/`git init` to copy the contents of the given directory (including any `hooks/` scripts) into the new repository's `.git` directory; those hooks execute on subsequent git operations. `StackCommands#fetch` performs exactly such a `git_clone`/`git fetch` when populating `@stack.git_path`, and `with_temporary_working_directory` subsequently runs `git clone` from that cache and `git checkout`.

No existing guard intercepts this: `verify_signature`/`GitHubApp#verify_webhook_signature` only ensure the webhook came from GitHub (an attacker can still author the underlying PR/label content that GitHub forwards); `ExplicitParameters` only validates types/presence, not content; `EnvironmentVariables#permit` is bypassed entirely for the `fetch` code path since it's simply never invoked.

### Impact Explanation
An attacker controlling a fork PR and its labels on a repo configured with `provisioning_behavior: prevent_with_label` can smuggle a chosen `GIT_TEMPLATE_DIR` (or any other environment variable name uppercased from a label, e.g. `LD_PRELOAD`-style vectors are not directly exploitable this way since git ignores unrelated names, but `GIT_TEMPLATE_DIR`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_PROXY_COMMAND` all are) into the environment of the `git fetch`/`git clone` process run on the Shipit deploy host for that review stack. This is Command execution on the deploy host (Critical — RCE class), scoped to the repository/stack owning that review stack, but repeatable on every PR update/label change and on every repository using `prevent_with_label` review stacks.

### Likelihood Explanation
Preconditions: the target repository's `shipit.yml` must configure `provisioning_behavior: prevent_with_label` (or otherwise instantiate `ReviewStack`), and a `ReviewStack`/`PullRequest` record must exist and be active. The attacker cost is very low — opening a PR from their own fork and applying a label with the desired name (assuming they have label-write access to their own PR, as stated in the threat model) is trivial and free, and the labeled webhook is repeatable at will.

### Recommendation
Apply the same whitelist-based sanitization used for deploy/rollback/task envs to the fetch-related code paths: filter `@stack.env`/`StackCommands#env` through an explicit allowlist (e.g., only `ENVIRONMENT`, `LAST_DEPLOYED_SHA`, `GITHUB_REPO_OWNER`, `GITHUB_REPO_NAME`, `DEPLOY_URL`, `BRANCH`, and the git/base env keys) before it reaches `git(...)`/`Command.new` in `fetch`, `fetch_commit`, `fetched?`, and `fetch_deployed_revision`. Alternatively, restrict `ReviewStack#env`'s label-derived keys to a small explicit set of recognized flags (e.g., only allow keys the app itself defines, never arbitrary upcased label strings) rather than merging every label name into the process environment unconditionally.

### Proof of Concept
minitest plan (`test/unit/stack_commands_test.rb` or similar, hypothetical since `test/**` is out of scope for the audit but valid for a fix's regression test):
1. Build a `ReviewStack` with an associated `PullRequest` whose `labels` includes `"git_template_dir"`.
2. Call `stack.env` and assert `stack.env["GIT_TEMPLATE_DIR"] == "true"` — confirming the label reaches the stack env unfiltered [3](#0-2) .
3. Call `Shipit::StackCommands.new(stack).fetch` (or inspect the `Command` it builds) and assert the constructed `Command#env`/`unbundled_env` contains `"GIT_TEMPLATE_DIR" => "true"`, i.e. `Command.new(..., env: StackCommands.new(stack).env).unbundled_env["GIT_TEMPLATE_DIR"] == "true"` — proving the value reaches the spawned process's environment [11](#0-10) .
4. Contrast with `stack.build_deploy(...).env`, which must NOT contain `"GIT_TEMPLATE_DIR"` because `filter_deploy_envs` whitelists only `deploy_variables` [8](#0-7) , demonstrating the asymmetry between the protected deploy path and the unprotected fetch path.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L29-31)
```ruby
              requires :labels, Array do
                requires :name, String
              end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
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

**File:** lib/shipit/stack_commands.rb (L13-15)
```ruby
    def env
      super.merge(@stack.env)
    end
```

**File:** lib/shipit/stack_commands.rb (L17-35)
```ruby
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

**File:** lib/shipit/stack_commands.rb (L51-59)
```ruby
    def fetch_deployed_revision
      with_temporary_working_directory(commit: @stack.commits.reachable.last) do |dir|
        spec = DeploySpec::FileSystem.new(dir, @stack)
        outputs = spec.fetch_deployed_revision_steps!.map do |command_line|
          Command.new(command_line, env:, chdir: dir).run
        end
        outputs.find(&:present?).try(:strip)
      end
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

**File:** app/models/shipit/stack.rb (L161-172)
```ruby
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

**File:** app/models/shipit/deploy_spec.rb (L174-176)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end
```

**File:** lib/shipit/environment_variables.rb (L35-44)
```ruby
    def sanitize_env_vars(variable_definitions)
      allowed_variables = variable_definitions.map(&:name)

      allowed, disallowed = @env.partition { |k, _| allowed_variables.include?(k) }.map(&:to_h)

      error_message = "Variables #{disallowed.keys.to_sentence} have not been whitelisted"
      raise NotPermitted, error_message unless disallowed.empty?

      allowed
    end
```
