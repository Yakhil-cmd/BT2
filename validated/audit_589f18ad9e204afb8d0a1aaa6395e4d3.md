### Title
`repository.full_name` used by webhook handlers is never bound to the HMAC-verified `repository.owner.login` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/secret to verify the HMAC signature using `params.dig('repository','owner','login')`, but every `Handler` subclass looks up the target `Repository`/`Stack`/`ReviewStack` using the independent field `params.dig('repository','full_name')` (or `params.repository.full_name`). Nothing enforces `repository_owner == repository_name.split('/').first`, so a webhook whose signature is valid for org A can carry a `repository.full_name` pointing at org B's repository and mutate org B's `Stack`/`ReviewStack` rows.

### Finding Description
The broken binding, stated explicitly: the controller verifies `repository_owner = params.dig('repository','owner','login')` [1](#0-0)  against the org's `webhook_secret` in `verify_signature` [2](#0-1) , but `Handler#repository_name` independently reads `payload.dig('repository', 'full_name')` [3](#0-2)  and `Handler#stacks` resolves it via `Repository.from_github_repo_name(repository_name)` with no comparison back to `repository_owner` [4](#0-3) . `Repository.from_github_repo_name` performs a plain `find_by(owner:, name:)` lookup with no additional ownership check [5](#0-4) . The same disjoint pattern repeats in every pull-request handler (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, `AssignedHandler`), all of which build their own `repository` from `params.repository.full_name` rather than `repository_owner` [6](#0-5) .

Exploit flow: an attacker who legitimately administers their own org's Shipit GitHub App integration (and thus knows their own org's `webhook_secret`, a normal precondition of self-service/multi-tenant onboarding) crafts an arbitrary JSON body and computes a valid `X-Hub-Signature` HMAC with that secret. They set `repository.owner.login` to their own org (so `verify_signature` succeeds using their own org's app config) while setting `repository.full_name` to `"victim-org/victim-repo"`. `WebhooksController#create` then dispatches this to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [7](#0-6) . Inside the handler, `repository_name`/`params.repository.full_name` resolves to the victim's real `Repository` row and its `stacks`/`review_stacks`, entirely independent of the verified `repository_owner`.

Concretely, `PushHandler#process` will find the victim's matching `Stack` by branch and call `stack.sync_github(expected_head_sha: params.after)` [8](#0-7) , forcing an unsolicited `GithubSyncJob` for a stack the attacker's org does not own — a state mutation (`mark_as_accessible!`/`mark_as_inaccessible!`, commit appends, `lock_reverted_commits!`) triggered purely by the attacker's forged owner mismatch [9](#0-8) . More directly, `PullRequest::LabeledHandler`/`UnlabeledHandler`/`ClosedHandler`/`ReopenedHandler` call `ReviewStackAdapter#archive!`/`unarchive!`/`find_or_create!` against `repository.review_stacks` resolved from the spoofed `full_name`, and these methods act purely on attacker-supplied `params` (`stack.archive!(user, ...)`, `stack.unarchive!`, `create!` a new `ReviewStack`) with no re-validation of the true owner [10](#0-9) . This directly archives/unarchives/creates review stacks belonging to a repository whose org never authenticated the request.

Existing guards do not catch this: `drop_unhandled_event` and `check_if_ping` only gate on event type; `verify_signature` only checks HMAC validity for whatever org string happens to be in `repository.owner.login`, never cross-checking `repository.full_name`; `ExplicitParameters` schemas only validate types/presence of `repository.full_name`, not its owner segment; `Repository.from_github_repo_name` and model validations only enforce `owner`/`name` character-set format, not cross-tenant authorization [11](#0-10) .

### Impact Explanation
An attacker who controls (or self-service-configures) one org's webhook secret in a multi-tenant Shipit deployment can force state mutations on any other org's `Stack`/`ReviewStack`/`Commit` rows purely by mismatching `repository.owner.login` vs `repository.full_name` in the JSON body — no access to the victim org's secret, GitHub App, or Shipit session is required. This is repeatable against arbitrary victim repositories/stacks known to the attacker (by name) for every event type dispatched through `Handler#stacks`/`repository`, matching the "payload for one repository mutating another's stack, commit, task or team" Critical category.

### Likelihood Explanation
Exploitability requires the attacker to already control a valid `webhook_secret` for at least one org onboarded to the Shipit instance (a normal condition in self-service/multi-tenant GitHub App configurations, not a privileged Shipit role) and requires that the victim repository's owner/name be discoverable (public information). No GitHub interaction is required beyond crafting an HTTP POST with a correctly computed HMAC — trivial and repeatable at will.

### Recommendation
In `WebhooksController#verify_signature`/`create`, or in `Handler#initialize`/`repository_name`, assert that the owner segment of `payload.dig('repository','full_name')` matches `payload.dig('repository','owner','login')` (i.e., `repository_owner == repository_name.split('/').first`) before dispatching to handlers, rejecting the request with 422 otherwise. Enforce this centrally once (e.g. in `Handler#initialize` or a shared concern) so all subclasses inherit the check automatically rather than repeating ownership logic per handler.

### Proof of Concept
minitest plan (add to `test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/push_handler_test.rb`):
1. Create `victim_repo = Repository.create!(owner: 'victim-org', name: 'victim-repo')` and `victim_stack = Stack.create!(repository: victim_repo, branch: 'master', environment: 'production')`.
2. Build a push payload with `ref: 'refs/heads/master'`, `after: 'deadbeef'`, `repository: { owner: { login: 'attacker-org' }, full_name: 'victim-org/victim-repo' }`.
3. Stub `Shipit.github(organization: 'attacker-org')` to return a `GitHubApp` whose `verify_webhook_signature` returns `true` (simulating attacker knowing their own secret).
4. Assert the equality being tested: before dispatch, `repository_owner` (`'attacker-org'`) != `repository_name.split('/').first` (`'victim-org'`).
5. `post :create, body: payload.to_json, as: :json`.
6. Assert `GithubSyncJob` was enqueued with `stack_id: victim_stack.id` (`assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: 'deadbeef'])`), proving the attacker's own-org-signed webhook mutated a stack belonging to `victim-org`, which never authenticated the request.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-34)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L36-38)
```ruby
        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L41-45)
```ruby
    validates :name, uniqueness: { scope: %i[owner], case_sensitive: false,
                                   message: 'cannot be used more than once' }
    validates :owner, :name, presence: true, ascii_only: true
    validates :owner, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: OWNER_MAX_SIZE }
    validates :name, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: NAME_MAX_SIZE }
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-50)
```ruby
          def find_or_create!
            stack || create!
          end

          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```
