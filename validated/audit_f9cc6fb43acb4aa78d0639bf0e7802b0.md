Confirmed: `StackCommands#env` (used by `fetch` and `fetch_deployed_revision`) merges `Commands#env` (git/GitHub env) with `@stack.env`, and for a `ReviewStack` that `env` includes every pull-request label name uppercased mapped to `"true"` with no allowlist.

### Title
Unfiltered PR-label-derived env vars reach `Command#start`'s spawned process during `fetch`, allowing arbitrary env var injection (e.g. `LD_LIBRARY_PATH`) - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) into the stack's environment hash with no key allowlist, and this same `env` is passed unfiltered into `StackCommands#fetch`/`fetch_deployed_revision`, which build a `Command` that calls `Command#unbundled_env` (merging `@env` over `BASE_ENV`) before `PTY.spawn`. Any GitHub user who can label their own fork PR (a `pull_request` webhook is emitted automatically by GitHub with no signature bypass needed since this is their own repo) can therefore set an arbitrary environment variable name — including `LD_LIBRARY_PATH` — on the process spawned for `git fetch`/`git clone` and any fetch-deployed-revision command.

### Finding Description
The broken binding: `StackCommands#env` (`lib/shipit/stack_commands.rb:13-15`) should only forward vetted deploy environment variables to spawned commands, but instead `env == base_env.merge(stack.env)` where `stack.env` for a `ReviewStack` is unconditionally extended with attacker-controlled keys: [1](#0-0) 

This differs from the deploy/rollback path, which explicitly filters through an allowlist via `DeploySpec#filter_deploy_envs`/`#filter_rollback_envs` (`app/models/shipit/deploy_spec.rb:174-180`) using `EnvironmentVariables#permit`, which raises `NotPermitted` for any variable not declared in the repo's `shipit.yml` `deploy.variables`/`rollback.variables`. **No equivalent filtering exists for the `fetch` path** — `StackCommands#fetch` and `#fetch_deployed_revision` pass `env:` straight through to `Command.new`: [2](#0-1) 

`Command#unbundled_env` merges `@env.stringify_keys` last, overriding anything in `BASE_ENV`/`PATH`, and this is exactly what's handed to `PTY.spawn`: [3](#0-2) 

Exploit flow: an unprivileged fork-PR author opens/labels a PR with a label literally named `ld_library_path` (case-insensitive, since it's uppercased). GitHub's `pull_request` webhook (`opened`/`labeled`) is captured by `LabelCapturingHandler`, which persists the label names verbatim from the payload onto `PullRequest#labels` for any non-archived stack matching the repo: [4](#0-3) 

With `provisioning_behavior=allow_all` the review stack is provisioned/kept active regardless of labels (see `provision?` logic in `opened_handler.rb`/`reopened_handler.rb`), so `FetchDeployedRevisionJob`/scheduled fetches run `StackCommands#fetch`/`#fetch_deployed_revision` with the poisoned `env`, injecting `LD_LIBRARY_PATH=true` into the spawned `git` (or fetch-deployed-revision shell command) process.

**Caveat on impact**: the value forwarded is *always* the fixed string `"true"` (from `labels[label_name.upcase] = "true"`), not an attacker-chosen path — [5](#0-4) . So the attacker controls the *variable name* but not its *value*. For `LD_LIBRARY_PATH` specifically, a value of the literal string `"true"` is a relative directory name; the dynamic linker will search `$CWD/true` for shared objects if the spawned binary is dynamically linked and CWD is attacker-influenceable (the fetch/clone `chdir` is the stack's own git/deploy path, not attacker-controlled fork content at the time `LD_LIBRARY_PATH` takes effect for `git`/`sh` themselves). This makes reliable RCE via this specific variable non-trivial to demonstrate purely through this engine's code — it requires the attacker to also plant a `./true/*.so` in a directory that becomes CWD of a *later* dynamically-linked spawn, which is outside what this engine controls (test/PoC would need to show a concrete .so hijack scenario, which isn't demonstrated in the repo).

### Impact Explanation
The confirmed, in-scope defect is that **any pull-request label name becomes an unsanitized environment variable name reaching `PTY.spawn` for the `fetch` phase**, bypassing the allowlist mechanism (`EnvironmentVariables#permit`) that protects `deploy`/`rollback`. This can override variables such as `GIT_ASKPASS`, `GIT_SSH_COMMAND`-adjacent behavior is not directly settable this way, but arbitrary variable *names* (uppercased label) with value `"true"` can still clash with and override sensitive existing keys derived from `BASE_ENV`/`Shipit.env` for that specific stack's fetch commands (e.g., disabling git safety envs, or asserting boolean-like flags some tooling checks via `ENV['SOME_FLAG']`). The specific `LD_LIBRARY_PATH`→RCE chain requires an additional CWD/`.so`-planting step not demonstrated in this engine's code, so it does not on its own constitute a proven Critical RCE; it is best characterized as an unauthorized environment-variable injection into the `fetch` command execution for that one repository's own review stack (not cross-tenant, since labels only affect that PR's own `ReviewStack`).

### Likelihood Explanation
Preconditions: `provisioning_behavior=allow_all` (or `allow_with_label`/any config where the PR's stack stays active), a `ReviewStack` associated with the fork PR, and the attacker's ability to add a label to their own PR — all attacker-controlled, zero privilege required, fully repeatable per label add/webhook. The fixed `"true"` value constraint materially reduces exploitability for genuine RCE via `LD_LIBRARY_PATH` specifically.

### Recommendation
Apply the same allowlist filtering used for deploy/rollback (`DeploySpec#filter_deploy_envs`) to the `fetch`/`fetch_deployed_revision` environment before it reaches `Command.new`, or stop merging raw PR label names into `env` at all — instead expose them under a clearly-namespaced, non-overriding key (e.g., `SHIPIT_PR_LABEL_<NAME>`) and never let label-derived keys collide with reserved environment variable names like `LD_LIBRARY_PATH`, `PATH`, `GIT_ASKPASS`, etc.

### Proof of Concept
```ruby
# test/lib/shipit/stack_commands_fetch_env_test.rb
test "fetch env includes attacker-controlled LD_LIBRARY_PATH from PR label" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["ld_library_path"]

  env = StackCommands.new(stack).env

  assert_equal "true", env["LD_LIBRARY_PATH"]
  # binding claimed broken: fetch env should equal base_env (no attacker key),
  # but env["LD_LIBRARY_PATH"] == "true" != nil, proving the divergence.
end
```
This demonstrates the unfiltered key reaches `StackCommands#env`, which is passed directly into `Command.new(..., env:, ...)` for `git fetch`/`git clone` in `#fetch` (`lib/shipit/stack_commands.rb:27-35`), and from there into `Command#unbundled_env` → `PTY.spawn` (`lib/shipit/command.rb:92,103-105`).

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

**File:** lib/shipit/stack_commands.rb (L27-59)
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

    def fetched?(commit)
      if valid_git_repository?(@stack.git_path)
        git('rev-parse', *quiet_git_arg, '--verify', "#{commit.sha}^{commit}", env:, chdir: @stack.git_path)
      else
        # When the stack's git cache is not valid, the commit is
        # NOT fetched. To keep the interface of this method
        # consistent, we must return a Shipit::Command whose #success?
        # method returns false - has a non-zero exit status. We utilize
        # the POSIX 'test' command with no arguments which should
        # always have an exit status of 1.
        Command.new('test', env:, chdir: @stack.deploys_path)
      end
    end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L1-9)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      module PullRequest
        class LabelCapturingHandler < Shipit::Webhooks::Handlers::Handler
          params do
            requires :action, String
```
