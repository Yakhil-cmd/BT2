### Title
Unwhitelisted PR label injection into git transport env (`GIT_SSH_COMMAND`) via `ReviewStack#env` - (File: app/models/shipit/review_stack.rb, lib/shipit/stack_commands.rb)

### Summary
`ReviewStack#env` merges every pull request label name, upper-cased, into the stack environment hash with no whitelist, unlike task/deploy/rollback variable env merging which goes through `EnvironmentVariables#permit`. `StackCommands#env` (`super.merge(@stack.env)`) picks this hash up unfiltered and passes it straight into `Command.new(..., env:)`/`Command#unbundled_env` for `git fetch`/`git clone`, so a PR label literally named `GIT_SSH_COMMAND` becomes `GIT_SSH_COMMAND=true` in the environment of the git process that fetches that stack's commits.

### Finding Description
The broken binding: the transport command git executes for `fetch`/`clone` against `@stack.git_path` should be the SSH binary Shipit configured, i.e. `command.env['GIT_SSH_COMMAND']` should equal Shipit's configured value (unset/ssh wrapper), not an attacker-chosen string. Instead:

- `ReviewStack#env` [1](#0-0)  merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into `super` (i.e., `Stack#env`) with no name whitelist at all.
- `PullRequest#github_pull_request=` copies GitHub PR label names verbatim into `labels` [2](#0-1) , and `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` from the webhook payload with no name filtering [3](#0-2) .
- `StackCommands#env` does `super.merge(@stack.env)` [4](#0-3) , and for a `ReviewStack` this resolves to the labels-including `ReviewStack#env`. This same `env` is passed to `git('fetch', ...)`/`git_clone(...)` in `#fetch_commit`/`#fetch`/`#fetched?` [5](#0-4) .
- `TaskCommands#env` also starts with `super.merge(@stack.env)` before overriding a specific set of keys (`SHIPIT_USER`, `BUNDLE_PATH`, etc.) [6](#0-5) ; `GIT_SSH_COMMAND` is not among the overridden keys, so the label-derived value survives into deploy/clone commands too.
- `Command#initialize` stores `env` and stringifies values [7](#0-6) ; this is passed to `PTY.spawn`/subprocess execution with that environment, meaning `git` will treat `GIT_SSH_COMMAND=true` as the SSH transport program.

Attacker action: an unprivileged GitHub user who can open/label their own PR (label capture explicitly fires on `opened`/`labeled`/`unlabeled`/`reopened` webhook events, gated only by the PR belonging to an existing, non-archived `ReviewStack` for that repository [8](#0-7) ) can add a label literally named `GIT_SSH_COMMAND` to their own PR. This label is captured into `PullRequest#labels`, and the next `StackCommands#fetch`/`#fetch_commit`/`fetched?` call for that review stack will run `git` with `GIT_SSH_COMMAND=true` in its environment.

Existing guards (`EnvironmentVariables#permit`, `ExplicitParameters` schema, model validations) do not apply here because `ReviewStack#env` never calls `EnvironmentVariables.with(...).permit(...)` — that whitelist mechanism is used only for task/deploy/rollback user-supplied `env` params (`app/models/shipit/task_definition.rb#filter_envs`, `app/models/shipit/deploy_spec.rb#filter_deploy_envs`/`filter_rollback_envs`), not for PR-label-derived stack env. There is no repository/stack-side restriction on label names.

### Impact Explanation
When `git` is invoked with `GIT_SSH_COMMAND=true`, and the stack's git remote uses an `ssh://`/`git@host:` URL, git substitutes `true` as the transport program instead of `ssh`. `true` exits 0 immediately without transferring any data, so `git fetch`/`git clone` can appear to "succeed" (or, depending on git version/plumbing, fail cleanly) while never actually contacting the remote or updating the local cache. This lets a stale or previously cached revision stand in for what should be a freshly fetched commit for that specific review stack's `git_path`. The blast radius is scoped to the one review stack owned by the attacker's own PR/repository — this is a same-tenant integrity issue (the attacker degrades the accuracy of *their own* stack's fetched revision, not another tenant's), which limits it below "payload for one repository mutating another's stack." No credentials, RCE, or auth bypass is achieved; the effect is exclusively on git transport reliability/correctness. This is a real but narrow-impact override, closer to a caching/integrity nuisance for the same PR's own stack than the Critical/High categories in the rubric (which require RCE, auth bypass, secret exfiltration, cross-repository mutation, unauthorized deploy/rollback/merge, or team-authorization escalation).

### Likelihood Explanation
- Requires the target stack to be a `ReviewStack` with an SSH-based `repo_git_url` (many Shipit deployments use HTTPS + `GITHUB_TOKEN`, in which case `GIT_SSH_COMMAND` is irrelevant since git never invokes ssh).
- Requires the attacker to control a PR against a repo that already has an active, non-archived review stack.
- Attacker cost is trivial (add a label named `GIT_SSH_COMMAND`), fully repeatable, but only affects the fetch pipeline for that PR's own review stack — not other tenants' stacks or credentials.

### Recommendation
In `ReviewStack#env`, reject or filter label names that collide with reserved/security-sensitive environment variable names (e.g. `GIT_SSH_COMMAND`, `GIT_PROXY_COMMAND`, `PATH`, `IFS`, `BUNDLE_*`, `LD_PRELOAD`, etc.) before merging into the stack environment, or route label-derived env through an explicit whitelist/denylist the same way `EnvironmentVariables#permit` is used for task/deploy env. Additionally, `StackCommands#env`/`TaskCommands#env` should explicitly pin `GIT_SSH_COMMAND` (and other git transport-control variables) to Shipit-controlled values after merging `@stack.env`, mirroring the existing `BUNDLE_PATH` override pattern in `TaskCommands#env`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_env_test.rb
require 'test_helper'

module Shipit
  class ReviewStackEnvTest < ActiveSupport::TestCase
    test "PR label named GIT_SSH_COMMAND overrides git transport env in StackCommands" do
      stack = shipit_stacks(:review_stack) # a ReviewStack fixture
      stack.pull_request.update!(labels: ["GIT_SSH_COMMAND"])

      # Binding under test: StackCommands#env['GIT_SSH_COMMAND'] should equal
      # Shipit's configured ssh command (nil/unset), not the label-derived "true".
      commands = Shipit::StackCommands.new(stack)
      assert_equal "true", commands.env["GIT_SSH_COMMAND"]

      # Confirm it reaches the actual git command built for fetch_commit
      commit = stack.commits.last
      command = commands.fetch_commit(commit)
      assert_equal "true", command.env["GIT_SSH_COMMAND"]
    end
  end
end
```
This demonstrates the equality `StackCommands#env['GIT_SSH_COMMAND'] == 'true'` (attacker-controlled) instead of the expected absence/Shipit-controlled value, and that this value propagates unmodified into the `Command` object that would be executed via `PTY.spawn`.

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

**File:** app/models/shipit/pull_request.rb (L48-48)
```ruby
      self.labels = github_pull_request.labels.map(&:name)
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
