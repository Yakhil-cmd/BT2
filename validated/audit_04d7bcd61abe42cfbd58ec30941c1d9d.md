### Title
Webhook signature verification uses `repository.owner.login` but stack lookup uses `repository.full_name`, allowing cross-tenant `GithubSyncJob` triggering - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` authenticates a webhook against the GitHub App belonging to `params.dig('repository','owner','login')`, but `Handler#stacks` (used by `PushHandler#process`) resolves the target stack from the independent `payload.dig('repository','full_name')` field. Because these two fields are never checked for consistency, an attacker who owns any GitHub App configured in the same Shipit instance can forge a payload whose `repository.owner.login` is their own org (passing signature verification with their own `webhook_secret`) while `repository.full_name` names a victim's real stack, causing `GithubSyncJob` to run against that victim stack.

### Finding Description
The broken binding: **org that authenticated the payload (`repository.owner.login`, "attacker-org") == org owning the stack that gets synced (derived from `repository.full_name`, "victim-org")** is assumed but never enforced.

Trace:
- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) computes `github_app = Shipit.github(organization: repository_owner)`, where `repository_owner` (`webhooks_controller.rb:59-62`) reads `params.dig('repository', 'owner', 'login')` from the *raw, unparsed-into-record* JSON body. It then verifies `X-Hub-Signature` against that app's `webhook_secret`. [1](#0-0) [2](#0-1) 
- `#create` (`webhooks_controller.rb:10-15`) re-parses `request.raw_post` into `params` and passes the full JSON hash to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` — the entire payload, not just the pre-verified owner field. [3](#0-2) 
- `Handler#stacks` (`handler.rb:32-38`) resolves the target via `Repository.from_github_repo_name(repository_name)`, where `repository_name = payload.dig('repository', 'full_name')` — a completely separate field from the one used for signature verification. [4](#0-3) 
- `Repository.from_github_repo_name` (`repository.rb:53-56`) just splits `full_name` on `/` and does a plain `find_by(owner:, name:)` lookup with no relation to the app/org that authenticated the request. [5](#0-4) 
- `PushHandler#process` (`push_handler.rb:12-17`) then calls `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on the attacker-chosen branch — `params.after` is attacker-controlled and comes straight from the forged payload. [6](#0-5) 

Attacker request: POST `/webhooks` with header `X-Github-Event: push` and a valid `X-Hub-Signature` computed with attacker-org's own `webhook_secret`, body JSON containing `"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/production-app"}, "ref": "refs/heads/master", "after": "<attacker-chosen sha>"`.

Why existing guards fail:
- `drop_unhandled_event` only checks the event type is handled, not repository consistency.
- `verify_signature` only validates cryptographic authenticity against the org named in `repository.owner.login`; it never cross-checks that value against `repository.full_name`.
- `ExplicitParameters` schema in `PushHandler` only requires `ref` and `after` — it does not validate `repository.full_name` ownership.
- `Repository.from_github_repo_name` performs no authorization check; it is a pure DB lookup.

### Impact Explanation
The attacker forces `GithubSyncJob` to run against an arbitrary victim stack they do not own or administer, with an attacker-controlled `expected_head_sha`, causing the job to fetch commits via the victim stack's own GitHub API/App and insert them via `stack.commits.create_from_github!` (`app/jobs/shipit/github_sync_job.rb:18-49`), potentially triggering downstream auto-deploy behavior depending on the victim stack's configuration. [7](#0-6) 
This is a payload from one tenant (attacker-org) mutating another tenant's stack (victim-org) state — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is fully repeatable against any stack in the instance simply by changing `full_name`/`ref`/`after` in the forged body, as long as the attacker holds any valid GitHub App + `webhook_secret` pair configured on the same Shipit instance.

### Likelihood Explanation
Preconditions required: the attacker must own a GitHub App registered in the same multi-tenant Shipit instance (i.e., control `attacker-org`'s `webhook_secret`), which is a low bar in any multi-org Shipit deployment supporting self-service org registration or where the attacker is a legitimate customer of one org but targeting another org's stacks. No Shipit session, API token, or victim secret is needed. Cost is a single crafted HTTP POST with a correctly computed HMAC using the attacker's own secret. Fully repeatable and scriptable.

### Recommendation
In `verify_signature` and/or `Handler#stacks`, enforce that the GitHub App/organization used to verify the webhook signature matches the owner embedded in `repository.full_name` (and any other repository-identifying fields used later, e.g. `organization.login`, `repository.owner.login` used consistently). Reject the webhook (422) if they diverge, e.g. compare `repository_owner` against `payload.dig('repository','full_name').split('/').first` before dispatching to handlers.

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb`:
```ruby
test "push webhook signed by attacker-org cannot sync a stack belonging to victim-org" do
  attacker_org = 'attacker-org'
  victim_repo = shipit_repositories(:shipit) # owner e.g. 'victim-org', name 'production-app'
  victim_stack = shipit_stacks(:shipit)      # belongs_to victim_repo, branch 'master'

  Shipit.stubs(:github).with(organization: attacker_org).returns(
    stub(verify_webhook_signature: true)
  )

  payload = {
    ref: 'refs/heads/master',
    after: 'deadbeef' * 5,
    repository: {
      owner: { login: attacker_org },
      full_name: victim_repo.github_repo_name
    }
  }.to_json

  assert_enqueued_with(job: GithubSyncJob, args: [hash_including(stack_id: victim_stack.id)]) do
    post shipit.github_webhooks_path,
      params: payload,
      headers: {
        'X-Github-Event' => 'push',
        'X-Hub-Signature' => 'sha1=whatever',
        'Content-Type' => 'application/json'
      }
  end
end
```
Assert on both sides of the binding: `repository_owner` == `attacker-org` (used for signature check) vs. the stack actually enqueued belongs to `victim-org` (`victim_stack.repository.owner == 'victim-org'`) — demonstrating the divergence and unauthorized cross-tenant `GithubSyncJob` enqueue.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
