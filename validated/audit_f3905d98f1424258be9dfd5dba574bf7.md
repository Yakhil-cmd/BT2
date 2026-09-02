### Title
Unfiltered pull-request label names leak into deploy environment via `ReviewStack#env`, enabling `BUNDLE_GEMFILE` injection into `deploy.override` — (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) as an environment-variable key with value `"true"` into the stack's environment, and this merge is never passed through `EnvironmentVariables#permit`'s whitelist, unlike the deploy's own user-supplied env. Because `TaskCommands#env` unconditionally folds `@stack.env` into the environment used to build every `Command` (including the `deploy.override` step), and `Command#unbundled_env` layers `@env` on top of the sanitized base environment before `PTY.spawn`, an unprivileged fork PR author can set arbitrary environment-variable *names* — including `BUNDLE_GEMFILE` — on the spawned deploy process by simply naming a PR label `bundle_gemfile`.

### Finding Description
The broken binding: the set of keys reaching `PTY.spawn` for the `deploy.override` step should equal `filter_deploy_envs(deploy.env) ∪ machine_env ∪ fixed keys`, i.e. only whitelisted/known keys. Instead it equals that set **plus** `pull_request.labels.map(&:upcase) → "true"`, an attacker-controlled superset.

Path:
1. `ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`) does:
```ruby
super.merge(pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" })
```
with no key allowlist.
2. `LabelCapturingHandler#capture_labels` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102`) persists `params.pull_request.labels.map(&:name)` straight from the webhook body, with only a String-type schema check (no character/keyword restriction), so a label named e.g. `bundle_gemfile` is accepted verbatim.
3. `TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`) unconditionally does `super.merge(@stack.env).merge(...)`, so review-stack labels flow into every task's command env, including the `deploy.override` step built by `DeployCommands#perform` → `Command.new(command_line, env:, chdir:)`.
4. Only `Deploy#env` (the field set explicitly via UI/API) is sanitized, via `Stack#build_deploy` → `filter_deploy_envs(env.to_h)` → `EnvironmentVariables#permit(deploy_variables)` (`app/models/shipit/deploy_spec.rb:174-176`, `app/models/shipit/stack.rb:161-172`). `@stack.env` (the PR-label-derived hash) never passes through `EnvironmentVariables#permit`.
5. `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) builds `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)`. `BASE_ENV` already nils out ambient `BUNDLE_GEMFILE` (via `Bundler.unbundled_env`), but the attacker-controlled `@env` is merged last, re-introducing `BUNDLE_GEMFILE=true` verbatim into the argv passed to `PTY.spawn`.
6. Existing tests already demonstrate the unfiltered flow: `test/models/shipit/review_stack_test.rb:59-65` and `test/unit/deploy_commands_test.rb` (`#env includes the stack's pull request labels`) assert `stack.env["WIP"]`/`DeployCommands#env["WIP"]` are set straight from labels — proving there is no filtering step anywhere on this path.

Because GitHub's git protocol allows fetching a PR's exact head commit SHA from the base repository's remote (`git fetch origin <commit.sha>`, used in `StackCommands#fetch_commit`, `lib/shipit/stack_commands.rb:17-25`) even for commits that only exist in a fork, the attacker's fork content — including a file literally named `true` placed at the deploy working directory — is checked out into the stack's working directory as part of normal review-stack provisioning. If the repo's `deploy.override` (or `dependencies` install) step invokes `bundle` in any form, Bundler resolves `ENV['BUNDLE_GEMFILE']` (here the literal string `"true"`) relative to the current working directory and evaluates it as Ruby, executing attacker code on the deploy host.

No existing guard blocks this: `EnvironmentVariables#permit` is bypassed entirely for `stack.env`; `capture_labels` has no content restriction on label names beyond `String`; `filter_deploy_envs`/`deploy_variables` only cover the explicit `Deploy#env` field.

### Impact Explanation
Arbitrary code execution on the Shipit deploy host, triggered from the `deploy.override` (or dependency-install) command for the affected repository's review stack — a Critical RCE per the Immunefi class definition. The blast radius is scoped to the repository whose review stacks are enabled with `allow_with_label`/`allow_all`, but is fully repeatable: any fork PR author can relabel their PR (or open a new PR with the crafted label) to re-trigger the injection on every subsequent deploy/dependency run of that review stack.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled with `provisioning_behavior` allowing PR-driven provisioning (`allow_with_label` or `allow_all`), and its `shipit.yml` `deploy.override`/`dependencies` steps must invoke Bundler (a very common Capistrano/Ruby-app pattern documented in the engine's own README). Attacker cost is minimal: open a PR from a fork, add a label named `bundle_gemfile`, and include a file named `true` containing malicious Ruby in the PR branch. No secrets, tokens, or elevated GitHub role are required — this matches the "unprivileged fork PR author" threat model exactly.

### Recommendation
Do not merge pull-request label-derived environment variables into the command environment without passing them through `EnvironmentVariables#permit` against an explicit allowlist (e.g., `deploy_variables`/`rollback_variables`), exactly as is already done for `Deploy#env`. Additionally, block environment variable names known to affect subprocess/tool behavior (e.g., `BUNDLE_GEMFILE`, `RUBYOPT`, `LD_PRELOAD`) from ever being settable via label-derived or otherwise unauthenticated inputs, and consider stripping/blocklisting such keys unconditionally inside `Command#unbundled_env` regardless of `@env` contents.

### Proof of Concept
minitest plan (`test/models/shipit/review_stack_test.rb` or a new `test/unit/deploy_commands_test.rb` case), mirroring the pattern of the existing `"#env includes the stack's pull request labels"` test:

```ruby
test "[allow_with_label] BUNDLE_GEMFILE is injected into deploy.override env via an uppercased PR label" do
  stack = shipit_stacks(:review_stack)
  stack.repository.update!(provisioning_behavior: :allow_with_label)
  stack.pull_request.labels = ["bundle_gemfile"]

  deploy = stack.trigger_continuous_delivery
  commands = Shipit::DeployCommands.new(deploy).perform
  command = commands.first

  # Binding under test: deploy.override step env should NOT contain fork-controllable BUNDLE_GEMFILE
  refute command.env.key?("BUNDLE_GEMFILE"),
    "deploy.override step inherited fork-controllable BUNDLE_GEMFILE=#{command.env['BUNDLE_GEMFILE'].inspect}"
end
```
This test currently fails (the key `BUNDLE_GEMFILE` reaches `command.env` with value `"true"`), demonstrating the vulnerability without requiring a live GitHub connection, consistent with the already-present `DeployCommandsTest#env includes the stack's pull request labels` test that proves the unfiltered label-to-env path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
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

**File:** test/models/shipit/review_stack_test.rb (L59-65)
```ruby
    test "#env includes the stack's pull request labels" do
      stack = shipit_stacks(:review_stack)
      stack.pull_request.labels = ["wip", "bug"]

      assert_equal stack.env["WIP"], "true"
      assert_equal stack.env["BUG"], "true"
    end
```

**File:** test/lib/shipit/deploy_commands_test.rb (L1-16)
```ruby
# frozen_string_literal: true

require "test_helper"

class DeployCommandsTest < ActiveSupport::TestCase
  test "#env includes the stack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    deploy = stack.trigger_continuous_delivery
    stack.pull_request.labels = ["wip", "bug"]

    env = Shipit::DeployCommands.new(deploy).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
  end
end
```
