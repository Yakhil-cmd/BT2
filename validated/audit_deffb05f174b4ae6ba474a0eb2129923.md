### Title
Unauthenticated ReviewStack creation and command execution on arbitrary attacker branches, repeated per-PR without any authorization check - ([File: app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb])

### Summary
`ReviewStackAdapter#create!` builds every `ReviewStack`'s `branch` directly from the attacker-supplied `pull_request.head.ref` with no check that the ref belongs to an approved/authorized submitter, and this path is reachable even on repositories configured with `review_stacks_enabled: false` due to an operator-precedence bug in `OpenedHandler#provision?`. Because `create!` performs no capacity, ownership, or authorization check of any kind, each additional pull request opened against the same misconfigured repository independently creates a new `ReviewStack` whose attacker-controlled `branch` is fetched, checked out, and executed via `TaskCommands`/`Command#start`/`PTY.spawn`, with no aggregate or per-call gating that would stop the same trust violation from recurring N times.

### Finding Description
Binding claimed broken: `ref approved by Shipit for repository R == ref executed by Command#start for repository R`. Both sides are traced below and shown to diverge independently for every PR, not just once.

- `OpenedHandler#provision?` (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:65-70`) evaluates:
```ruby
repository.review_stacks_enabled &&
  repository.provisioning_behavior_allow_all? ||
  (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
  (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```
Ruby `&&` binds tighter than `||`, so this is `(review_stacks_enabled && allow_all?) || (allow_with_label? && labeled?) || (prevent_with_label? && !labeled?)`. When `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label`, the second disjunct is independent of `review_stacks_enabled` and evaluates true whenever the PR carries the configured label — so `review_stacks_enabled` does not actually gate provisioning for the `allow_with_label`/`prevent_with_label` behaviors. [1](#0-0) 

- Once `provision?` returns true, `OpenedHandler#process` calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!`, which calls `create!` for any never-before-seen `pr#{number}` environment. [2](#0-1) 

- `create!` sets `branch: params.pull_request.head.ref` straight from the webhook payload, with no validation against maintainer approval, no rate/capacity check, and no dedup beyond the PR-number-derived `environment` key — so each distinct PR number yields its own independent, unauthorized `ReviewStack`: [3](#0-2) 

- Each created stack is queued via `Shipit::ReviewStackProvisioningQueue.add(stack)` and later drives a `PerformTaskJob` → `TaskExecutionStrategy::Default#checkout_repository` / `perform_task`, which builds commands from `StackCommands#fetch`/`fetch_commit` (using `@stack.branch` — the attacker's ref) and `TaskCommands#perform` (running `@task.definition.steps`), each ultimately started by `Command#start`, which calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` on the deploy host: [4](#0-3) [5](#0-4) [6](#0-5) 

Nothing in this call chain — `create!`, `ReviewStackProvisioningQueue.add`, `PerformTaskJob`, `TaskCommands#perform`, `Command#start` — inspects how many stacks already exist for the repository, whether the caller is a maintainer, or whether the branch has been approved. Each of the N PRs the attacker opens independently reaches `create!` and independently produces a `Command`/`PTY.spawn` invocation against that PR's own `head.ref`, so the binding (`ref executed == ref approved`) is violated once per PR, not just once in aggregate. Existing guards do not stop this: `provision?`'s precedence bug defeats `review_stacks_enabled`, there is no `require_permission!`/`User#authorized?` check anywhere in `OpenedHandler` or `ReviewStackAdapter#create!`, and model validations on `Stack#branch`/`environment` only check format, not ownership.

### Impact Explanation
Each opened PR independently causes the deploy host to fetch and run commands against attacker-controlled branch content for the misconfigured repository — Critical (RCE via `Command`/`PTY.spawn`) per the existing finding, and this holds per-PR: an attacker can obtain as many independent unauthorized execution instances as PRs they open, each with a distinct `branch`/`environment`/commit. Blast radius is scoped to the single misconfigured repository (the `provision?` precedence bug applies per-`Repository` row), but within that repository the attacker is not limited to one exploitation — they get one unauthorized `Stack`/execution per PR they open, all before any Shipit operator intervenes.

### Likelihood Explanation
Same preconditions as the base finding: the target repository must have `provisioning_behavior: allow_with_label` (or `prevent_with_label`) configured with `review_stacks_enabled: false`, and the attacker must be able to open PRs with (or without, for `prevent_with_label`) the configured label — both of which an unprivileged GitHub user with a fork can do. No Shipit secrets or elevated GitHub permissions are required. Repeating the attack is trivial: opening a second, third, ... Nth PR with a new branch name costs the attacker nothing extra and triggers the identical code path independently each time.

### Recommendation
Fix the operator-precedence bug in `OpenedHandler#provision?` by parenthesizing so `review_stacks_enabled` gates all three provisioning behaviors:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Additionally, `ReviewStackAdapter#create!` should not run any command against a PR branch until the PR author/head has been authorized (e.g., verifying the PR author or a subsequent approval against `Shipit.github_teams` or a repository maintainer list) — this closes both the single-PR and repeated-PR instances of the same violation.

### Proof of Concept
```ruby
test "review_stacks_enabled: false does not block allow_with_label provisioning, and each labeled PR independently creates an unauthorized stack" do
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :allow_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  payload_a = payload_parsed(:pull_request_opened)
  payload_a["number"] = 101
  payload_a["pull_request"]["number"] = 101
  payload_a["pull_request"]["head"]["ref"] = "attacker-branch-a"
  payload_a["pull_request"]["labels"] = [{ "name" => "pull-requests-label" }]

  payload_b = payload_parsed(:pull_request_opened)
  payload_b["number"] = 102
  payload_b["pull_request"]["number"] = 102
  payload_b["pull_request"]["head"]["ref"] = "attacker-branch-b"
  payload_b["pull_request"]["labels"] = [{ "name" => "pull-requests-label" }]

  assert_difference -> { Shipit::Stack.count }, 2 do
    OpenedHandler.new(payload_a).process
    OpenedHandler.new(payload_b).process
  end

  stack_a = repository.review_stacks.find_by(environment: "pr101")
  stack_b = repository.review_stacks.find_by(environment: "pr102")

  assert_equal "attacker-branch-a", stack_a.branch
  assert_equal "attacker-branch-b", stack_b.branch
  refute_equal stack_a.id, stack_b.id
  # Binding check: repository.review_stacks_enabled == false on both sides,
  # yet ref executed (stack.branch) was set from unauthenticated PR head.ref for BOTH stacks independently.
  assert_equal false, repository.reload.review_stacks_enabled
end
```

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-70)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def pull_request
            params.pull_request
          end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-98)
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

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end

          def environment
            "pr#{params.number}"
          end
```

**File:** app/models/shipit/task_execution_strategy/default.rb (L68-83)
```ruby
      def checkout_repository
        unless @commands.fetched?(@task.until_commit).tap(&:run).success?
          # acquire_git_cache_lock can take upto 15 seconds
          # to process. Try to make sure that the job isn't
          # marked dead while we attempt to acquire the lock.
          @task.ping
          @task.acquire_git_cache_lock do
            @task.ping
            unless @commands.fetched?(@task.until_commit).tap(&:run).success?
              capture!(@commands.fetch_commit(@task.until_commit))
            end
          end
        end
        capture_all!(@commands.clone)
        capture!(@commands.checkout(@task.until_commit))
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

**File:** lib/shipit/command.rb (L85-101)
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
```
