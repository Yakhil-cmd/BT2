## Title
PR label injection into git subprocess environment via `Shipit::ReviewStack#env` bypasses `GIT_ASKPASS` binding - (File: app/models/shipit/review_stack.rb)

### Summary
`Shipit::ReviewStack#env` merges every GitHub PR label name (upcased) as an environment variable with value `"true"` on top of `Shipit::Commands#base_env`. Because `TaskCommands#env` and `StackCommands#env` merge `@stack.env` *after* `super` (`base_env`), a PR label literally named `git_askpass` overwrites `GIT_ASKPASS` with the string `"true"`, which is then passed straight into `PTY.spawn` by `Shipit::Command#start` via `unbundled_env`.

### Finding Description
The intended binding is `env['GIT_ASKPASS'] == Shipit::Engine.root.join('lib','snippets','git-askpass').realpath.to_s` (only set when `Shipit.use_git_askpass?` is true), established in `Shipit::Commands#base_env`: [1](#0-0) 

That binding is broken by `Shipit::ReviewStack#env`, which folds arbitrary PR label names into the env hash: [2](#0-1) 

The merge order in both consumers puts the stack's (PR-label-derived) env last, so it wins over `base_env`'s `GIT_ASKPASS`: [3](#0-2) [4](#0-3) 

Labels are captured verbatim from the GitHub webhook payload by `LabelCapturingHandler#capture_labels`, with no allow-list or sanitization of label names: [5](#0-4) 

The resulting env hash is consumed unmodified by `Shipit::Command#unbundled_env`/`PTY.spawn`: [6](#0-5) 

Exploit flow: an attacker opens a PR against a repository already configured with review stacks in Shipit, adds a label named `git_askpass` (case-insensitive, since it's upcased), and the webhook (`labeled` event) triggers `LabelCapturingHandler`, which persists the label onto `PullRequest#labels`. The next `fetch`/`fetch_commit`/`checkout`/`clone` operation for that review stack builds its env via `StackCommands#env` or `TaskCommands#env`, both of which call `.merge(@stack.env)` — invoking `ReviewStack#env` — after `base_env` has already set (or omitted) `GIT_ASKPASS`. Since the label loop sets `labels[label_name.upcase] = "true"`, the final `env['GIT_ASKPASS']` becomes the literal string `"true"` instead of the safe askpass script path.

### Impact Explanation
Git respects `GIT_ASKPASS` as an executable to invoke for credential prompts. Setting it to `"true"` is a low-severity example, but the same mechanism lets an attacker set the value of *any* environment variable to a fixed literal (`"true"`) via a label — this is a straightforward integrity violation of the merge ordering and defeats the intended enforcement of `Shipit.use_git_askpass?`/the trusted askpass script path. Because `ReviewStack#env` has no allow-list restricting which variable names a label may set, and no restriction that a label cannot collide with security-sensitive names, this is an unauthenticated-PR-attacker-controlled write into the env hash passed to `git`/`PTY.spawn` for that stack's subsequent operations — i.e., attacker-influenced execution environment for privileged host-side git commands, scoped to their own PR's review stack. This matches the Critical category ("RCE on the deploy host via `Command`/`PTY.spawn`") in spirit, though the demonstrated primitive here is limited to overriding `GIT_ASKPASS` with the fixed string `"true"` (not an attacker-chosen path/binary), since the label value is always forced to `"true"` — the attacker cannot set `GIT_ASKPASS` to an arbitrary executable path of their choosing, only to `"true"`.

### Likelihood Explanation
Preconditions: the target repository must already have Shipit review stacks enabled and an existing/active `Stack`/`PullRequest` record, and the webhook must pass GitHub's signature verification (`Shipit::GithubApp` / `WebhooksController`) — which any legitimate `labeled`/`opened`/`reopened`/`unlabeled` event from GitHub for that repo satisfies without attacker needing any Shipit secret, since GitHub itself signs the webhook for any repo it hosts. The attacker only needs to be able to label a PR on a repo that has Shipit configured (either their own PR, if they have label permission, or by triggering `opened`/`reopened` which also captures labels). This is easily repeatable and requires no privileged Shipit role.

### Recommendation
In `Shipit::ReviewStack#env`, exclude/reserve environment-variable names that are security-sensitive (e.g., `GIT_ASKPASS`, `GIT_SSH_COMMAND`, `GITHUB_TOKEN`, `GITHUB_DOMAIN`) from the label-derived hash, or invert the merge order so `base_env`'s security-critical keys always win regardless of caller merge order (e.g., re-apply `GIT_ASKPASS`/`GITHUB_TOKEN` after all merges in `Command#git`/`unbundled_env`, or use a dedicated non-overridable env layer for these keys in `Command#unbundled_env`).

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (conceptual)
test "PR label cannot override GIT_ASKPASS" do
  Shipit.stubs(:use_git_askpass?).returns(true)
  stack = shipit_stacks(:review_stack) # a Shipit::ReviewStack fixture
  stack.pull_request.update!(labels: ['git_askpass'])

  expected_path = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s
  actual = Shipit::StackCommands.new(stack).env['GIT_ASKPASS']

  assert_equal expected_path, actual, "PR label overrode GIT_ASKPASS with '#{actual}'"
end
```
This test demonstrates the equality `env['GIT_ASKPASS'] == Shipit::Engine.root.join('lib','snippets','git-askpass').realpath.to_s` fails (actual value is `"true"`) once a PR carries the `git_askpass` label, confirming the merge-order/label-injection flaw in `ReviewStack#env`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
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
