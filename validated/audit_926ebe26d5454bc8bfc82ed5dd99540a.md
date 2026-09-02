### Title
Cross-tenant webhook authorization bypass via mismatched `repository.owner.login` vs `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a signature using `repository_owner` (read from `payload['repository']['owner']['login']` or `payload['organization']['login']`), while `Shipit::Webhooks::Handlers::Handler#stacks` (used by `PushHandler#process`) resolves the target `Repository`/`Stack` using a completely different field, `payload['repository']['full_name']`. Because nothing cross-validates that these two fields refer to the same organization, an attacker who legitimately owns one configured GitHub org/webhook_secret on a multi-tenant Shipit instance can forge a payload whose `repository.owner.login` is their own org (so the signature check passes with their own real secret) but whose `repository.full_name` names a victim org/repo, causing `PushHandler` to act on the victim's stack.

### Finding Description
The broken binding: `repository_owner` (used to pick the `GitHub App`/secret for `verify_webhook_signature`) == `repository.full_name`'s owner segment (used to resolve the `Stack` that gets mutated). These are never asserted equal.

Code path:
- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` (fallback `organization.login`) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)`. [1](#0-0) [2](#0-1) 
- `Handler#stacks` (base class used by `PushHandler`) resolves the target repository using `payload.dig('repository','full_name')`, an entirely separate field from the one used for signature/org selection. [3](#0-2) 
- `PushHandler#process` then queries `stacks.not_archived.where(branch:)` and calls `stack.sync_github(expected_head_sha: params.after)` for every matching stack, with no re-check that the stack's owning org matches the org whose secret validated the request. [4](#0-3) 

Exploit: the attacker (who legitimately owns "attacker-org" as one of the multiple configured GitHub Apps documented in `docs/setup.md`'s "Using Multiple Github Applications" section) sends `POST /webhooks` with `X-Github-Event: push`, a valid `X-Hub-Signature` computed with attacker-org's real `webhook_secret`, and a JSON body where `repository.owner.login = "attacker-org"` but `repository.full_name = "victim-org/victim-repo"`, `ref = "refs/heads/<victim's continuously-deployed branch>"`, `after = "<attacker-chosen sha>"`. `verify_signature` passes (attacker-org's secret matches attacker-org's own signature). `PushHandler` then resolves the *victim's* stack via `full_name` and enqueues `GithubSyncJob` for it.

Why guards fail: `verify_signature`'s only check is HMAC validity against the org named in `repository.owner.login`; it never confirms that org owns the repo named in `repository.full_name`, and `drop_unhandled_event`, `ExplicitParameters` schema (`PushHandler` only requires `ref` and `after`), and model validations do nothing to bind these two fields together.

### Impact Explanation
This is a cross-tenant authentication bypass: a party who only controls their own org's webhook secret can cause `Shipit` to process a push event against a different org's stack, i.e., "a payload for one repository mutating another's stack" — the exact scenario the impact list calls out. Concretely, `GithubSyncJob.perform_later(stack_id: victim_stack.id, expected_head_sha: attacker_sha)` is enqueued for the victim's stack despite the request never being authenticated by the victim org.

However, tracing further into `GithubSyncJob#perform`, `expected_head_sha` is **not** used to fetch or inject commit content — it is only consulted via `commit_exists?(expected_head_sha)` to decide whether to schedule a retry when GitHub eventual-consistency hasn't caught up yet. [5](#0-4) 
The actual commits appended come from `stack.github_commits`, which queries the real (victim) GitHub repository/branch, so the attacker cannot inject a forged commit or force a deploy of an arbitrary, non-existent sha. The demonstrable, reproducible impact is therefore limited to: unauthorized cross-tenant triggering of a resync job against the victim's stack (forcing an out-of-band `GithubSyncJob`/`CacheDeploySpecJob` run) — not a forged deploy of attacker-controlled content. This still qualifies as an authentication-bypass class issue (forged webhook accepted, wrong-tenant binding), but the "attacker forces a deploy of an attacker-chosen sha" claim in the prompt is not supported by the code and should be treated as unconfirmed/incorrect.

### Likelihood Explanation
Preconditions: the Shipit instance must be configured with multiple GitHub organizations (per `docs/setup.md`), the attacker must be one of those legitimate configured orgs (so they know their own real `webhook_secret`), and a victim stack with a matching branch name must exist. Given those, the attack is a single unauthenticated HTTP POST with no GitHub interaction required, fully repeatable against any branch name shared between attacker's knowledge and a victim stack.

### Recommendation
In `PushHandler`/`Handler#stacks` (or centrally in `WebhooksController`), require that the org used to verify the webhook signature (`repository_owner`) matches the org prefix of `repository.full_name` before resolving/mutating any `Stack`, rejecting the request (422) otherwise.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/push_handler_test.rb` or `test/controllers/webhooks_controller_test.rb`):
1. Configure two GitHub orgs in test secrets (`attacker-org`, `victim-org`) with distinct `webhook_secret`s (mirrors `test/dummy/config/secrets_double_github_app.yml`).
2. Create `victim_stack` under repository `victim-org/victim-repo`, `branch: "master"`, `continuous_deployment: true`.
3. Build a push payload: `repository.owner.login = "attacker-org"`, `repository.full_name = "victim-org/victim-repo"`, `ref = "refs/heads/master"`, `after = "<attacker sha>"`.
4. Sign the raw JSON body with `attacker-org`'s real `webhook_secret` (HMAC-SHA1), set as `X-Hub-Signature`.
5. Assert: `Shipit.github(organization: 'attacker-org').verify_webhook_signature(sig, body)` returns `true` (attacker-side equality holds), while `victim_stack.repository.owner` ("victim-org") != "attacker-org" (cross-tenant equality fails).
6. `assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: attacker_sha]) { post :create, body: payload, as: :json }` — confirms the enqueue happens despite the mismatch, proving the binding break; separately assert (via stubbing `Stack#github_commits`) that no forged commit content is injected, to bound the actual impact to unauthorized job triggering rather than data forgery.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-33)
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
```
