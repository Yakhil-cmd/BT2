### Title
`Repository#review_stacks_enabled` is bypassed in `provision?` due to `&&`/`||` precedence, allowing unauthorized `ReviewStack` creation on repos with review stacks disabled - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` intends to gate all provisioning on `repository.review_stacks_enabled`, but Ruby operator precedence only groups `review_stacks_enabled` with the first `allow_all?` clause. When `provisioning_behavior` is `allow_with_label` (or `prevent_with_label`), `review_stacks_enabled` is never consulted, so a PR labeled by its own (unprivileged) author on a repo with review stacks explicitly disabled still causes a `ReviewStack` to be created and provisioned.

### Finding Description
The broken binding: the operator's intent is `review_stacks_enabled == true` must equal a precondition for provisioning under **any** `provisioning_behavior`. The code instead implements:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Due to Ruby `&&`/`||` precedence, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

So when `review_stacks_enabled == false` and `provisioning_behavior == :allow_with_label`, and the PR carries `repository.provisioning_label_name`, the second disjunct alone evaluates true, making `provision?` true — independent of `review_stacks_enabled`.

Path: `process` calls `respond_to_pull_request_opened?` → `provision?` [2](#0-1) , which if true triggers `ReviewStackAdapter.new(params, ...).find_or_create!` → `create!`, building a `ReviewStack` with `branch: params.pull_request.head.ref` taken directly from the attacker's PR head ref, and `environment: "pr#{params.number}"` [3](#0-2) . This stack is queued via `ReviewStackProvisioningQueue.add(stack)`, and downstream `GithubSyncJob#perform` fetches commits and calls `CacheDeploySpecJob.perform_later(stack)` [4](#0-3) , which checks out `shipit.yml` from the attacker-controlled branch.

The attacker's exact request: open a pull request from their own fork against the target repo, with a label matching `repository.provisioning_label_name`, and push a webhook (`pull_request` `opened` event) to Shipit. Note the webhook itself still requires a valid signature (`verify_signature` in `WebhooksController`) [5](#0-4)  — but this signature is computed and sent by GitHub itself when the PR event fires (any GitHub user opening a PR and adding a label on a repo where the Shipit GitHub App/webhook is installed triggers this legitimately-signed event), not by the attacker directly. The attacker only needs the ability to open a PR and add a label to it, both of which are actions available to any external contributor with fork/PR access, no Shipit credentials needed.

Existing guards (`verify_signature`, `ExplicitParameters` schema, `drop_unhandled_event`) validate the webhook's authenticity and payload shape, but do not touch the business-logic bug in `provision?`, and no model validation on `Repository` or `ReviewStack` enforces `review_stacks_enabled` at creation time — `stack_attributes` and `scope.create!` proceed unconditionally once `provision?` returns true.

### Impact Explanation
An unprivileged contributor can force Shipit to create and provision a `ReviewStack` (and downstream sync/deploy-spec jobs) for a repository whose operator explicitly disabled review stacks (`review_stacks_enabled: false`), as long as `provisioning_behavior` happens to be `allow_with_label`. This is an unauthorized-record-creation / policy-bypass vulnerability: a repository-level authorization control (`review_stacks_enabled`) is completely ignored for two of the three `provisioning_behavior` modes. It leads to Shipit fetching and later checking out attacker-controlled branch content (`shipit.yml`) for `CacheDeploySpecJob`, which is a step toward command execution against the deploy host in Shipit's task-execution pipeline. This matches "Critical - unauthorized deploy/mutation" per the given severity list, since it results in a stack/record being created for a repository that explicitly opted out of this behavior, driven by an unauthenticated (relative to Shipit) external actor's PR content. Repeatable against any repository configured with `review_stacks_enabled: false` + `provisioning_behavior: allow_with_label` (or `prevent_with_label`, where merely omitting the label suffices), by any GitHub user able to open PRs against it.

### Likelihood Explanation
Requires only a specific but plausible repository configuration: `review_stacks_enabled: false` combined with `provisioning_behavior: allow_with_label` (or `prevent_with_label`) [6](#0-5) . No Shipit secrets, sessions, or GitHub App credentials are needed by the attacker — the GitHub-originated webhook is legitimately signed since it's a real PR event. Attacker cost is minimal (open a PR, add a label they control on their own PR). This is a straightforward, deterministic logic bug (operator precedence), fully reproducible without live GitHub, using a unit test on `OpenedHandler`/`ReviewStackAdapter`.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates all three provisioning behaviors:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` (existing file, out-of-scope to modify per rules but illustrating the intended assertion):
1. Create a `Shipit::Repository` fixture/factory with `review_stacks_enabled: false`, `provisioning_behavior: "allow_with_label"`, `provisioning_label_name: "ship-it"`.
2. Build webhook params for a `pull_request` `opened` event on that repo, with `pull_request.labels` containing `{ name: "ship-it" }` and `pull_request.head.ref` set to an attacker-chosen branch (e.g. `"attacker-branch"`).
3. Assert binding before: `repository.review_stacks_enabled == false` and expect `Shipit::Stack.count` (or `Shipit::ReviewStack.count`) to remain unchanged after calling `OpenedHandler.new(...).process` (or `.call(params)`).
4. Actual (bug) result: `Shipit::ReviewStack.count` increases by 1, and `Shipit::ReviewStack.last.branch == "attacker-branch"`, demonstrating `review_stacks_enabled == false` did not prevent stack creation — violating the intended equality `review_stacks_enabled(at webhook time) == review_stacks_enabled(at provision time) == false ⇒ no stack created`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-63)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
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

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
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

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
```
