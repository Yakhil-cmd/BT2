### Title
Unfiltered pull-request label injection into `fetch` command env allows attacker-controlled `GIT_CONFIG_GLOBAL` key - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) as an environment-variable key with a hard-coded value `"true"`, with no allowlist, and this merged hash flows unfiltered into `StackCommands#fetch`'s `git` invocations via `Command#unbundled_env`. An unprivileged fork-PR author on a repo configured with `provisioning_behavior=allow_with_label` can therefore make the `fetch` step's spawned `git` process see an env var named `GIT_CONFIG_GLOBAL` (or any other git-sensitive variable name), but its value is fixed to the literal string `"true"`, not attacker-chosen content.

### Finding Description
The claimed broken binding is: `fetch step env keys == deploy-variable allowlist keys`. In fact:
- `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase] = "true" }` into the stack env with no key allowlist [1](#0-0) .
- `StackCommands#env` (used by `fetch`, `fetch_commit`, `fetched?`, `fetch_deployed_revision`) is `super.merge(@stack.env)`, i.e. it directly folds in this unfiltered label hash [2](#0-1) .
- `StackCommands#fetch` passes this `env:` straight into `git(...)`/`Command.new` with no call to `EnvironmentVariables#permit` [3](#0-2) .
- By contrast, `deploy`/`rollback` env do go through an allowlist (`filter_deploy_envs`/`filter_rollback_envs` via `EnvironmentVariables#permit`, which raises `NotPermitted` for unlisted keys) [4](#0-3) [5](#0-4)  — but `fetch` has no equivalent filter.
- `Command#unbundled_env` merges `BASE_ENV`, then `PATH`, then `@env.stringify_keys` last, so any key present in `@env` (including one named `GIT_CONFIG_GLOBAL`) overrides whatever `BASE_ENV` would otherwise contain, and reaches `PTY.spawn` [6](#0-5) .

However, the value assigned to the injected key is always the hard-coded string `"true"` — `labels[label_name.upcase] = "true"` — never attacker-supplied content [7](#0-6) . This is confirmed by the existing test asserting `env["WIP"] == "true"` [8](#0-7) . The question's exploit narrative ("supplies an attacker git config file defining a hook or fsmonitor command") requires the attacker to control the *value* of `GIT_CONFIG_GLOBAL` so it points to a file with malicious content they authored. Here the value is unconditionally `"true"`, not a path the attacker can freely choose. For this to work as RCE, git would additionally have to resolve `GIT_CONFIG_GLOBAL=true` as a relative path to a file literally named `true` sitting in the working directory at the exact moment `git fetch`/`git clone` executes, and that file would need to already contain a working malicious git config (e.g., a hook or `core.fsmonitor` directive) BEFORE the fetch pulls fresh content — during `fetch`, `chdir` is `@stack.git_path` (the server-managed git cache) or `@stack.deploys_path`, not the attacker's freshly-fetched working tree, so there's no reliable point in the traced `fetch` path where such an attacker-authored file is guaranteed to be present in the CWD before or during the very `git fetch` call that carries the poisoned env. I could not fully verify within the available context whether any later step (e.g., checkout, submodule handling) re-uses this same unfiltered `@stack.env`-derived value with a CWD that does contain attacker content, which would be required to complete the RCE chain as claimed.

### Impact Explanation
The demonstrated primitive is real: an arbitrary environment-variable **key** (matching any label name, uppercased) is unconditionally injected into commands spawned during the `fetch` phase, with no allowlist, unlike deploy/rollback which are filtered. This is a genuine allowlist-bypass/environment-injection bug in `StackCommands#fetch`. However, the specific "Critical RCE via attacker git config" impact requires attacker control of the *value*, not just the key, and the value is hard-coded to `"true"`. Without a demonstrated, reachable point where a git process reads a file at that fixed relative path from a directory populated with attacker content, the RCE chain as specifically described is not established by the traced code alone.

### Likelihood Explanation
Preconditions (`provisioning_behavior=allow_with_label`, opening/labeling a PR) are trivial for an unprivileged forker, and the key-injection into `fetch`'s env is unconditional and always reachable. But turning that into RCE requires the additional, unverified step of an attacker-controlled file at a matching relative path being present in the working directory used by a subsequent `git` invocation that honors `GIT_CONFIG_GLOBAL=true`. That linkage was not established from the code paths inspected (`fetch`/`fetch_commit`/`fetched?`/`fetch_deployed_revision`, all operating on server-managed cache/deploy directories at invocation time).

### Recommendation
Regardless of the RCE feasibility gap, `StackCommands#fetch` (and `fetch_commit`, `fetched?`, `fetch_deployed_revision`) should apply the same key allowlist used for deploy/rollback (`EnvironmentVariables#permit`) before merging `@stack.env`/label-derived variables into the git command environment, explicitly excluding git-sensitive names like `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_SSH_COMMAND`, `GIT_ALLOW_PROTOCOL`, etc. `ReviewStack#env` should also not allow pull-request label names to define arbitrary environment variable keys with no allowlist.

### Proof of Concept
Not confirmed as a complete RCE PoC within the traced code; the only firmly reproducible assertion is that a label named `git_config_global` results in `stack.env["GIT_CONFIG_GLOBAL"] == "true"` reaching `StackCommands#fetch`'s spawned `git` process env, mirroring the existing pattern in `test/models/shipit/review_stack_test.rb:59-65` and `test/lib/shipit/deploy_commands_test.rb`. Extending this to actual `PTY.spawn` env inspection during `fetch` (e.g., stubbing `Command#start`/`PTY.spawn` and asserting `"GIT_CONFIG_GLOBAL" => "true"` is present in the passed env hash for `StackCommands#fetch`) would validate the key-injection primitive, but does not by itself demonstrate command execution of attacker-chosen content.

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

**File:** lib/shipit/stack_commands.rb (L13-15)
```ruby
    def env
      super.merge(@stack.env)
    end
```

**File:** lib/shipit/stack_commands.rb (L27-35)
```ruby
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

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
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

**File:** test/models/shipit/review_stack_test.rb (L59-65)
```ruby
    test "#env includes the stack's pull request labels" do
      stack = shipit_stacks(:review_stack)
      stack.pull_request.labels = ["wip", "bug"]

      assert_equal stack.env["WIP"], "true"
      assert_equal stack.env["BUG"], "true"
    end
```
