## Analysis

**Binding claimed to be broken:** the question assumes attacker can set both the *name* AND *value* of an arbitrary env var (e.g. `GIT_CONFIG_KEY_0=core.fsmonitor`, `GIT_CONFIG_VALUE_0=<attacker command>`) via pull-request labels, so that `git fetch` in `StackCommands#fetch_commit` ( [1](#0-0) ) executes attacker code.

**Actual binding:** `ReviewStack#env` builds the label-derived hash as `labels[label_name.upcase] = "true"` — the *value* is hard-coded to the literal string `"true"` for every label, regardless of label content. [2](#0-1) 

This hash is merged into `StackCommands#env` (`super.merge(@stack.env)`, [3](#0-2) ), then into `Command#env`, and ultimately into the process env passed to `PTY.spawn` via `unbundled_env` in `Command#start`. [4](#0-3) 

So while the attacker **can** control the *key* of an injected env var (e.g. name a label `git_config_count` to set `GIT_CONFIG_COUNT`), they can **never** control its *value* — it is always the string `"true"`, never an integer or an arbitrary git-config value/command. `LabelCapturingHandler#capture_labels` does persist raw label names verbatim from the webhook body ( [5](#0-4) ), confirming the key-injection primitive is real, but the exploit chain in the question requires attacker-controlled **values** for `GIT_CONFIG_KEY_0`/`GIT_CONFIG_VALUE_0` (to point git config at `core.fsmonitor`/`core.hooksPath`/`alias.*` with a malicious command string). That is impossible here: even `GIT_CONFIG_KEY_0` and `GIT_CONFIG_VALUE_0`, if set via labels named accordingly, would themselves only ever equal `"true"`, not `core.fsmonitor` or a shell command. Likewise `GIT_CONFIG_COUNT` can only become the string `"true"`, which git's `strtoul`-based parsing treats as `0`/invalid, not a usable positive count.

Both sides of the equality (`attacker-desired env value` vs. `actual env value produced by ReviewStack#env`) diverge: the code path only allows key injection with a fixed, non-actionable value, so the described RCE primitive (arbitrary `GIT_CONFIG_KEY_N`/`GIT_CONFIG_VALUE_N` pairs) cannot be constructed from pull request labels.

#No vulnerability found for this question.

### Citations

**File:** lib/shipit/stack_commands.rb (L13-15)
```ruby
    def env
      super.merge(@stack.env)
    end
```

**File:** lib/shipit/stack_commands.rb (L17-25)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```
