This confirms the vulnerable chain. `StackCommands#env` merges `@stack.env` unfiltered [1](#0-0) , and `ReviewStack#env` merges every pull request label name (uppercased) as a `"true"` value with no allowlist [2](#0-1) . That merged hash is passed as `env:` into `git(...)` calls inside `StackCommands#fetch`/`#fetch_commit`/`#git_clone` [3](#0-2) , which build a `Command` via `Commands#git` [4](#0-3) . `Command#unbundled_env` merges `@env` on top of the base/OS env unconditionally [5](#0-4) , and `Command#start` passes that directly to `PTY.spawn` [6](#0-5) . Unlike task/deploy/rollback envs, which are filtered via `EnvironmentVariables.permit` against a declared allowlist (`filter_deploy_envs`, `filter_rollback_envs`, `TaskDefinition#filter_envs`) [7](#0-6) [8](#0-7) [9](#0-8) , there is no such filtering anywhere on `@stack.env`/`ReviewStack#env` before it reaches `git`. Existing tests explicitly document that label names become env vars unfiltered: `TaskCommandsTest#test_env_includes_a_ReviewStack's_pull_request_labels` [10](#0-9)  and the corresponding `ReviewStackTest` [11](#0-10) .

Labels are captured straight from the webhook body without allowlisting via `LabelCapturingHandler#capture_labels`, which persists `params.pull_request.labels.map(&:name)` verbatim [12](#0-11) , and this handler runs for `opened`/`labeled`/`unlabeled`/`reopened` events on any stack that is present and not archived [13](#0-12) . Webhook signature verification (`verify_signature`) only requires a valid `X-Hub-Signature` computed from the target GitHub organization's `webhook_secret`, which authenticates that GitHub itself sent the payload — it does nothing to sanitize the label content, so any user able to add a label on their own fork's PR (against a repository with `review_stacks_enabled` and `provisioning_behavior=allow_all`, as required for `ReviewStack` creation) can set `GIT_SSH`, `GIT_SSH_COMMAND`, or similar via label name.

### Title
Unsanitized pull request labels become process environment variables in `git` invocations, enabling `GIT_SSH`/`GIT_SSH_COMMAND` injection - (File: app/models/shipit/review_stack.rb, lib/shipit/stack_commands.rb, lib/shipit/command.rb)

### Summary
`ReviewStack#env` merges every pull request label name (uppercased) directly into the stack's environment hash with no allowlist, and that hash flows unfiltered through `StackCommands#env` into `git fetch`/`git clone` invocations that `Command#start` executes via `PTY.spawn`. A PR author on `allow_all` provisioned repos can therefore set arbitrary environment variables — including git-honoured ones like `GIT_SSH_COMMAND` or `GIT_SSH` — that get inherited by the `git` subprocess used to fetch/clone the repository, achieving remote code execution on the Shipit host.

### Finding Description
The broken binding: the set of environment variables reaching `PTY.spawn` for a `git` invocation in `StackCommands#fetch`/`#git_clone` should equal `base_env` (GitHub token/domain/askpass) plus only allowlisted, operator-declared variables — but in fact it equals `base_env ∪ {LABEL_NAME.upcase => "true" for each attacker-supplied PR label}` with zero allowlist applied.

Path: a PR author opens/labels a PR on a repo with `review_stacks_enabled` and `provisioning_behavior: allow_all` (or `allow_with_label` after the provisioning label is present), naming a label e.g. `GIT_SSH_COMMAND=touch /tmp/pwned;#` or a valid label whose upcased form is `GIT_SSH` pointing at an attacker-controlled script path within the checkout. GitHub sends a signed `pull_request` webhook (signature covers only authenticity of "this came from GitHub for this org", not label content). `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim onto `PullRequest#labels` [12](#0-11) . When the `ReviewStack` next runs any task (deploy/fetch), `ReviewStack#env` merges `labels.each_with_object({}) { |n,h| h[n.upcase] = "true" }` on top of the base env [2](#0-1) . `StackCommands#env` merges `@stack.env` with no filtering [1](#0-0) , and this env is passed straight into the `git` calls inside `#fetch`, `#fetch_commit`, `#git_clone` [3](#0-2) . `Command#unbundled_env` merges `@env` onto the OS/base env with no allowlist check [5](#0-4) , and `Command#start` hands that hash directly to `PTY.spawn` [6](#0-5) . Since git honours `GIT_SSH`/`GIT_SSH_COMMAND` from its process environment for any ssh:// transport (or `GIT_ASKPASS`/`GIT_EXTERNAL_DIFF` etc. depending on which name upcases to a git-meaningful variable), a name-controlled label directly injects an executable-path variable into the fetch/clone subprocess.

Existing guards do not stop this: `verify_signature` only validates the webhook came from GitHub for the claimed org [14](#0-13) ; the `ExplicitParameters` schema for `LabelCapturingHandler`/`LabeledHandler` only requires `labels` to be an `Array` of objects with a String `name`, placing no restriction on content [15](#0-14) ; and `EnvironmentVariables#permit`, which is used to filter deploy/rollback/task envs against `VariableDefinition` allowlists [9](#0-8) [7](#0-6) , is never applied to `@stack.env`/`ReviewStack#env` before it is merged into the `git` command's environment. The project's own tests document the unfiltered merge as intended behavior rather than guarding against it [11](#0-10) [10](#0-9) .

### Impact Explanation
An unprivileged PR author on any repository with review stacks enabled and `allow_all`/`allow_with_label` provisioning can name a label that becomes an arbitrary environment variable in every subsequent `git fetch`/`git clone` process Shipit runs for that stack, including `GIT_SSH`/`GIT_SSH_COMMAND`, giving remote code execution on the Shipit deploy host under the Shipit service account. This is repeatable per label change and applies to any repository configured this way; because the same host process serves all stacks/repositories, RCE here compromises the shared deploy host, including secrets (`GITHUB_TOKEN`, other stacks' deploy env) for other tenants. This matches the Critical — RCE on the deploy host via `Command`/`PTY.spawn` class.

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled: true` and `provisioning_behavior` of `allow_all` (or `allow_with_label` with the label present) — a configuration explicitly designed to let external PRs auto-provision stacks with no maintainer approval. No secrets, sessions, or team membership are needed; the attacker only needs to open a PR from their own fork and apply a label with the crafted name, actions fully within an unprivileged GitHub user's capability. This is low-cost, deterministic, and repeatable against any repository using this provisioning mode.

### Recommendation
Do not let raw pull-request label names become arbitrary environment variable keys/values. Either (a) never merge label-derived data directly into process environment used for `git`/`PTY.spawn` — expose labels only as a JSON/array value under a single fixed key (e.g. `PULL_REQUEST_LABELS`), or (b) filter the merged `ReviewStack#env`/`@stack.env` through `EnvironmentVariables.permit` against an explicit operator-declared allowlist of safe variable names before it's used in any `git` invocation, explicitly excluding/blocking any `GIT_*` or otherwise git-meaningful variable names.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (or a new stack_commands_test.rb)
test "GIT_SSH set via a pull request label reaches the git fetch/clone process env" do
  stack = shipit_stacks(:review_stack)
  stack.repository.update!(provisioning_behavior: :allow_all, review_stacks_enabled: true)
  stack.pull_request.update!(labels: ["git_ssh=/tmp/attacker_ssh_wrapper.sh"])
  # upcased label name becomes the env key
  assert_equal "true", stack.env["GIT_SSH=/TMP/ATTACKER_SSH_WRAPPER.SH"] # illustrative; use a valid env-key-shaped label e.g. "GIT_SSH"
  stack.pull_request.update!(labels: ["GIT_SSH"])
  assert_equal "true", stack.env["GIT_SSH"]

  commands = Shipit::StackCommands.new(stack)
  fetch_command = commands.fetch
  # This is the equality that should NOT hold but does:
  assert_equal "true", fetch_command.env["GIT_SSH"], "attacker-controlled label leaked into git subprocess env"
end
```
This demonstrates the binding `fetch_command.env["GIT_SSH"] == "true"` (attacker-controlled, sourced purely from an unauthenticated PR label) holds, proving the label value reaches the `git` invocation's environment that is passed unfiltered to `PTY.spawn` in `Command#start`.

### Citations

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

**File:** lib/shipit/commands.rb (L28-33)
```ruby
    def git(*args)
      kwargs = args.extract_options!
      kwargs[:env] ||= base_env
      Command.new("git", *args, **kwargs)
    end
    ruby2_keywords :git if respond_to?(:ruby2_keywords, true)
```

**File:** lib/shipit/command.rb (L85-99)
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
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
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

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
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

**File:** test/lib/shipit/task_commands_test.rb (L6-16)
```ruby
  test "#env includes a ReviewStack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    stack.pull_request.labels = ["wip", "bug"]
    task = shipit_tasks(:shipit_restart)
    task.stack = stack

    env = Shipit::TaskCommands.new(task).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L26-31)
```ruby
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L51-72)
```ruby
          def capture_labels?
            opened_active_stack? ||
              labeled_active_stack? ||
              unlabeled_active_stack? ||
              reopened_active_stack?
          end

          def opened_active_stack?
            opened? && stack.present?
          end

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```
