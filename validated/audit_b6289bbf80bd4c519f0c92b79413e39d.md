### Title
Attacker-controlled PR label overrides `GIT_ASKPASS` in git fetch commands - ([File: app/models/shipit/review_stack.rb])

### Summary
`Shipit::ReviewStack#env` merges every pull-request label (upcased) into the stack's environment hash as `LABEL => "true"`, and this hash is merged *on top of* `Commands#base_env` in `Shipit::StackCommands#env`. An attacker who can label their own pull request on a repository with `review_stacks_enabled` and `provisioning_behavior: allow_all` can set a label named `git_askpass`, which overwrites the `GIT_ASKPASS` environment variable that `Commands#base_env` sets to the trusted `lib/shipit/snippets/git-askpass` script, replacing it with the literal string `"true"` for every subsequent `git` command run against that stack's cache (fetch, `fetched?`, clone).

### Finding Description
The binding the codebase relies on is:
`Commands#base_env['GIT_ASKPASS'] == Shipit::Engine.root.join('lib','snippets','git-askpass').realpath.to_s` (set only when `Shipit.use_git_askpass?` is true) [1](#0-0) .

That binding is broken by the following merge chain:
1. `LabelCapturingHandler#capture_labels` persists arbitrary attacker-supplied label names verbatim into `pull_request.labels` for `opened`/`labeled`/`unlabeled`/`reopened` events on a non-archived stack: `pull_request.update!(labels: params.pull_request.labels.map(&:name))` [2](#0-1) .
2. `Shipit::ReviewStack#env` turns every label into an uppercased env key set to `"true"` and merges it **over** the base `Stack#env`: `super.merge(pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" })` [3](#0-2) .
3. `Shipit::StackCommands#env` merges the stack's env **on top of** `Commands#base_env`: `super.merge(@stack.env)` [4](#0-3) . Since `@stack.env` is merged last, a label `git_askpass` → key `GIT_ASKPASS` → `"true"` silently clobbers the askpass script path that `base_env` had set.
4. This merged env is passed explicitly into `fetched?`, `fetch`, and `fetch_commit`, e.g. `git('rev-parse', ..., env:, chdir: @stack.git_path)` [5](#0-4) .
5. `Command#initialize` stores `@env` as-is, and `Command#unbundled_env` merges it last over `BASE_ENV`, so the override survives into the spawned process: `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)`, then `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [6](#0-5) [7](#0-6) .

No existing guard filters or reserves label names before they are turned into environment keys — `capture_labels` performs no denylisting of e.g. `GIT_ASKPASS`, `GITHUB_TOKEN`, `BUNDLE_*`, etc. `EnvironmentVariables#permit`/interpolation logic is unrelated (it only guards template substitution, not this raw hash merge). The webhook signature check is legitimate here — the attacker doesn't need to forge it; they only need to open/label a real PR on a repository the operator has configured with `review_stacks_enabled` + `provisioning_behavior: allow_all`, which is the documented "auto-provision stacks for every PR" mode.

### Impact Explanation
When `git` operates over HTTPS and needs to prompt for credentials (e.g., private repo fetch, or any prompt path), git invokes the program named by `GIT_ASKPASS`. Normally that's `lib/shipit/snippets/git-askpass`, which echoes back `GITHUB_USER`/`GITHUB_TOKEN` only in response to git's specific username/password prompts. With `GIT_ASKPASS=true`, the credential-prompt control is defeated: `true` unconditionally exits 0 with no output, silently answering any interactive prompt (blank username/password) instead of running the intended script. This does not directly leak `GITHUB_TOKEN` to the attacker in this path, but it removes the intended credential-handling safety net around interactive git prompts for that stack's own repository fetch, and demonstrates that PR label content — fully attacker-controlled on a repository configured for auto-provisioning — is turned into raw environment variables for privileged host commands executed via `PTY.spawn`. This is scoped to the targeted repository's own review stacks (an attacker cannot use it to affect another repository's stack), which limits blast radius to tenants that both enable `review_stacks_enabled` and `provisioning_behavior: allow_all`.

### Likelihood Explanation
Requires: the target repository has `review_stacks_enabled: true` and `provisioning_behavior: allow_all` (an operator choice, but a documented/supported and plausible configuration for open contribution repos). Given that, any GitHub user who can open a pull request against that repo and label it (or have it auto-labeled through their own control of the source branch, depending on repo permission model) can set the label. Attacker cost is minimal — one PR, one label — and the effect is repeatable on every fetch (`fetched?`, `fetch`, `fetch_commit`) for that stack for as long as the label remains, without any additional privilege.

### Recommendation
In `Shipit::ReviewStack#env` (or in `Shipit::PullRequest::LabelCapturingHandler#capture_labels`), reject/skip label names that collide with reserved/security-sensitive environment variable keys (e.g. `GIT_ASKPASS`, `GITHUB_TOKEN`, `GITHUB_DOMAIN`, `PATH`, `BUNDLE_*`, `GIT_*`) before merging them into the environment hash, or invert the merge order so `base_env`'s security-critical keys cannot be overridden by stack/label-derived env vars.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (conceptual)
test "pull request label cannot override GIT_ASKPASS" do
  Shipit.stubs(:use_git_askpass?).returns(true)
  stack = shipit_stacks(:review_stack)
  stack.pull_request.update!(labels: ["git_askpass"])

  expected_askpass = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s

  env = Shipit::StackCommands.new(stack).env

  assert_equal expected_askpass, env["GIT_ASKPASS"]  # currently fails: env["GIT_ASKPASS"] == "true"
end
```
This asserts the binding `base_env['GIT_ASKPASS'] == StackCommands.new(stack).env['GIT_ASKPASS']`; with the current code the label overwrite makes the right-hand side `"true"`, breaking the equality and confirming the vulnerability.

### Citations

**File:** lib/shipit/commands.rb (L37-50)
```ruby
    def base_env
      @base_env ||= begin
        env = Shipit.env.merge(
          'GITHUB_DOMAIN' => github.domain,
          'GITHUB_TOKEN' => github.token
        )

        if Shipit.use_git_askpass?
          env['GIT_ASKPASS'] = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s
        end

        env
      end
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

**File:** lib/shipit/stack_commands.rb (L37-49)
```ruby
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

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```
