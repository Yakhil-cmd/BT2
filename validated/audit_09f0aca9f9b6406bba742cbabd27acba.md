### Title
Outside-contributor fork PRs are provisioned and deployed as trusted Review Stacks with no fork-authorship check - ([File: app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb])

### Summary
`ReviewStackAdapter#stack_attributes` sets `branch: params.pull_request.head.ref` straight from an unauthenticated `pull_request.opened` webhook payload, with no check that `pull_request.head.repo` equals the base `repository`. When a repository has `review_stacks_enabled` and `provisioning_behavior: allow_all`, this lets any outside contributor cause Shipit to provision a `ReviewStack` and later execute the fork's `shipit.yml` steps via `TaskCommands`/`Command`/`PTY.spawn`, with `GITHUB_TOKEN` present in the deploy environment.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't: `pull_request.head.repo.full_name == repository.full_name` should be verified before any commit from `pull_request.head` is trusted for execution, but no code checks this anywhere in the path.

Path: `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler#process` calls `provision?`, which for a repo configured `provisioning_behavior_allow_all?` returns true purely based on `repository.review_stacks_enabled` [1](#0-0)  - with no inspection of `pull_request.head.repo`. It then calls `ReviewStackAdapter#find_or_create!` → `create!` → `stack_attributes`, which sets `branch: params.pull_request.head.ref` verbatim from the webhook payload [2](#0-1) . The `ReviewStack` is queued for provisioning immediately after creation [3](#0-2) .

When the stack is later deployed, `StackCommands#fetch_commit`/`fetch` run `git fetch origin ... commit.sha` or `git fetch origin ... @stack.branch` against `@stack.git_path`/`@stack.repo_git_url` [4](#0-3) , and `TaskCommands#checkout` checks out `commit.sha` directly [5](#0-4) . `TaskCommands#perform`/`install_dependencies` build `Command` objects from `deploy_spec.dependencies_steps!`/`@task.definition.steps` (i.e., `shipit.yml`) merged with an `env` hash that includes `GITHUB_TOKEN`-bearing credentials and runs them via `Command`/`PTY.spawn` [6](#0-5) . Nowhere in `TaskCommands`, `StackCommands`, `ReviewStack`, or `ReviewStackAdapter` is `pull_request.head.repo` compared against `repository` before checkout/execution.

Root cause: `Repository#provisioning_behavior_allow_all?` and `review_stacks_enabled` are the only gates on provisioning (see `app/models/shipit/repository.rb` lines 21-31 and `opened_handler.rb` lines 65-70), and this gate is authorization for "auto-provision any incoming PR," not authorization for "trust this PR's fork content to run shell commands with secrets." The `stack.branch`/checked-out `commit.sha` are attacker-named/attacker-authored values persisted unconditionally.

### Impact Explanation
Once provisioned, the review stack's deploy pipeline fetches and checks out the exact commit named in the PR's `head.sha`/`head.ref`, which for a fork PR is fully attacker-controlled content (including a malicious `shipit.yml`). Those steps run through `Command`/`PTY.spawn` with the stack's merged `env`, which includes `GITHUB_TOKEN` and other deploy-time environment variables [7](#0-6) . This is Critical: RCE on the deploy host, plus exfiltration of `GITHUB_TOKEN` and any other secrets injected into the task environment, triggered purely by opening a pull request against a repository configured for automatic review-stack provisioning. The blast radius is scoped to any repository that has `review_stacks_enabled` + `provisioning_behavior: allow_all` (or `allow_with_label` if the attacker can self-apply a label, or `prevent_with_label` if they simply omit it), which is a normal, documented, maintainer-chosen configuration for review-app workflows.

### Likelihood Explanation
Preconditions are exactly the ones described: `repository.review_stacks_enabled? == true` and `provisioning_behavior_allow_all?` (or an achievable label state under the other modes), which is a legitimate, expected Shipit configuration for teams that want automatic PR preview environments - not a misconfiguration that requires attacker-controlled secrets. The attacker needs only to open a PR from their own fork; no Shipit credentials, session, or GitHub org membership are required. This is fully repeatable against any repository configured this way, and each PR yields a fresh `ReviewStack`/task execution.

### Recommendation
Before provisioning or deploying a review stack, verify `pull_request.head.repo.full_name == repository.full_name` (i.e., reject or flag fork-authored PRs), and/or require the configured provisioning label / maintainer approval for any PR whose head repo differs from the base repo, regardless of `provisioning_behavior`. Persist a `fork_authored` flag on `ReviewStack`/`PullRequest` derived from the webhook payload and refuse to run `shipit.yml` steps for fork-authored stacks unless explicitly approved by an authorized user (e.g., via a maintainer-only label or comment command), analogous to GitHub Actions' "approval required for first-time contributors."

### Proof of Concept
Minitest plan (to be added under `test/`, not included here per scope, but described for reference):
1. Build a `pull_request.opened` payload where `pull_request.head.repo.full_name != repository.full_name` (fork) and `pull_request.head.ref`/`head.sha` are attacker-chosen.
2. Assert, after `OpenedHandler.new(params).process`, that `Shipit::ReviewStack.find_by(environment: "pr#{number}").branch == params.pull_request.head.ref` with no stored attribute distinguishing base-repo vs fork authorship (i.e., `ReviewStack`/`PullRequest` schema has no `head_repo_full_name`/`fork_authored` column).
3. Assert that `Shipit::TaskCommands#checkout`/`#clone` and `Shipit::StackCommands#fetch_commit`/`#fetch` never reference `pull_request.head.repo` or compare it to `stack.repository`, confirming no re-verification gate exists before `Command#start`/`PTY.spawn` runs `deploy_spec` steps.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-70)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-85)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L87-94)
```ruby
          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
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

**File:** lib/shipit/task_commands.rb (L17-27)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
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

**File:** lib/shipit/task_commands.rb (L50-59)
```ruby
    def checkout(commit)
      git(
        '-c',
        'advice.detachedHead=false',
        'checkout',
        '--quiet',
        commit.sha,
        chdir: @task.working_directory
      )
    end
```
