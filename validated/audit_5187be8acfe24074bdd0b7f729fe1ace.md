### Title
Cross-repository webhook forgery via unbound `repository.owner.login` (signature scope) vs `repository.full_name` (mutation target) - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/push_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify the HMAC using `repository.owner.login`, while `Handler#stacks` (used by `PushHandler#process`) resolves the target `Repository`/`Stack` using the independent, attacker-controlled `repository.full_name` field. Because these two fields are never cross-checked, an attacker who controls a repository (and its valid App webhook secret) in `attacker-org` can sign a payload that names an arbitrary victim `full_name`, causing `Stack#sync_github` to run against a stack owned by a different organization than the one whose secret verified the request.

### Finding Description
The broken binding, stated as an equality: `organization_whose_secret_verified_bytes` (`params.dig('repository','owner','login')`, used in `verify_signature`) `== organization_owning_synced_stack` (derived from `params.dig('repository','full_name')`, used in `Handler#stacks`) — this is **FALSE** and nothing in the code enforces it.

- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and looks up the GitHub App config via `Shipit.github(organization: repository_owner)`, then verifies the raw request body HMAC against that org's `webhook_secret`: [1](#0-0)  and [2](#0-1) .
- On success, `create` parses the full JSON body and dispatches it unchanged to `PushHandler.call(params)`: [3](#0-2) .
- `Handler#stacks` resolves the target repository from `payload.dig('repository', 'full_name')` — a completely separate field from the one used for signature scoping: [4](#0-3) .
- `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on the matching branch: [5](#0-4) .
- `Stack#sync_github` enqueues `GithubSyncJob` with the attacker-supplied `expected_head_sha`, which fetches commits from GitHub and appends them to the stack, potentially advancing `HEAD` and triggering continuous deployment: [6](#0-5) , [7](#0-6) .

**Attacker's exact request:** POST `/webhooks` with `X-Github-Event: push`, a valid `X-Hub-Signature` computed with `attacker-org`'s webhook secret, and body:
```json
{
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/repo"},
  "ref": "refs/heads/main",
  "after": "newsha-attacker-controls"
}
```
`verify_signature` passes because it only checks `attacker-org`'s secret against `repository.owner.login = "attacker-org"`. `Handler#stacks` then looks up `Repository.from_github_repo_name("victim-org/repo")` — completely disjoint from the verified scope — and processes `victim-org`'s stack.

**Why existing guards fail:** `verify_signature` and `Repository.from_github_repo_name` read two independent, both attacker-controlled JSON fields (`repository.owner.login` and `repository.full_name`), and nothing asserts `repository.full_name.split('/').first == repository.owner.login`. `ExplicitParameters` schema in `PushHandler` only validates presence of `ref`/`after`, not repository ownership consistency: [8](#0-7) . No model validation (`Repository` format/uniqueness) or `Stack` scope filters by "which org's secret verified this request."

### Impact Explanation
This is a payload for one repository mutating another organization's stack, matching the explicitly listed Critical category. Concretely, `Stack#sync_github(expected_head_sha:)` enqueues `GithubSyncJob`, which fetches commits via `stack.github_commits` (using the *victim's* GitHub App credentials) and appends new commits, moving the victim stack's tracked head. If the victim stack has `continuous_deployment` enabled, this can trigger an unauthorized deploy of attacker-influenced commits. The attack is repeatable against any victim repository whose `owner/name` the attacker can guess or discover, from any organization the attacker legitimately controls a webhook secret for — cross-tenant blast radius limited only by knowledge of target `full_name` values (which are public GitHub repo names).

### Likelihood Explanation
Preconditions: attacker needs a GitHub App installation (or org) with a valid, known `webhook_secret` for `attacker-org` — achievable by installing Shipit's GitHub App on a repository/org the attacker controls, or by any org configured in `Shipit.github` multi-org config. The attacker crafts the HTTP request directly (no GitHub UI interaction, no privileged Shipit role needed) and computes a valid HMAC using their own secret over the attacker-chosen body. Cost is low and the exploit is repeatable per request against any target `full_name` with an active tracked stack.

### Recommendation
In `Handler#stacks` (or centrally in `WebhooksController`), enforce that the repository used to resolve the signature-verifying organization matches the repository used to resolve the target `Stack`/`Repository`. Concretely, verify `payload.dig('repository', 'owner', 'login')` equals the owner segment of `payload.dig('repository', 'full_name')` before dispatching to handlers, or resolve the `Repository`/`Stack` strictly by an authenticated owner value rather than trusting `full_name` independently.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or handler-level test), no live GitHub:
1. Create `Repository` `owner: 'victim-org', name: 'repo'` with a `Stack` `branch: 'main'`, `archived_since: nil`.
2. Stub `Shipit.github(organization: 'attacker-org')` (or configure a fixture secret) so `verify_webhook_signature` returns `true` for a payload signed with `attacker-org`'s secret.
3. POST to `/webhooks` with `X-Github-Event: push`, valid signature for `attacker-org`, and body `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/repo"}, "ref": "refs/heads/main", "after": "newsha-attacker-controls"}`.
4. Assert:
   - `verify_signature` succeeds (response is not 422).
   - `assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: 'newsha-attacker-controls'])` — proving the equality `attacker-org == victim-org` (the binding under test) is false yet the job still ran against the victim's stack. [9](#0-8)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L7-10)
```ruby
        params do
          requires :ref
          requires :after
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

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
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

**File:** test/controllers/webhooks_controller_test.rb (L23-32)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
    end
```
