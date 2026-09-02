### Title
Cross-repository GithubSyncJob forgery via unbound `repository_owner`/`repository.full_name` in webhook signature verification - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook using the organization named in `repository.owner.login` (or `organization.login`), but the handler that actually mutates state (`PushHandler#process` via `Handler#stacks`) selects the target `Stack` using the wholly independent `repository.full_name` field from the same attacker-controlled JSON body. Because these two fields are never checked for equality, an attacker who legitimately owns a GitHub App installation for their own org can sign a payload with their own `webhook_secret` while pointing `repository.full_name` at any victim repository, causing Shipit to enqueue a `GithubSyncJob` against a stack the attacker does not control.

### Finding Description
The broken binding, stated explicitly: `repository_owner` (`params.dig('repository','owner','login')`, verified against a specific org's `webhook_secret`) is assumed to equal the organization segment of `repository.full_name` (used later to select the `Stack`) — this equality is never enforced.

Code path:
1. `WebhooksController#verify_signature` computes `repository_owner` purely from `params.dig('repository', 'owner', 'login')` and looks up `Shipit.github(organization: repository_owner)` to obtain that org's `webhook_secret`, then calls `verify_webhook_signature(signature, raw_post)` over the *entire raw body*. [1](#0-0) [2](#0-1) 
2. Because the attacker owns `attacker-org` and has installed the Shipit GitHub App there, they legitimately possess the ability to produce a valid HMAC-SHA1 signature over an arbitrary raw body using `attacker-org`'s own `webhook_secret` (delivered to them by GitHub for events on their own repos, or simply computable since it's their own registered secret). `verify_webhook_signature` only checks the signature against the raw bytes — it does not parse or validate that `repository.owner.login` matches any other field in the body. [3](#0-2) 
3. `WebhooksController#create` parses the body and dispatches to `Handler`, which independently derives the target repository from `payload.dig('repository', 'full_name')`: [4](#0-3) 
4. `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack of that repository matching the branch: [5](#0-4) 

Attacker's exact request: POST `/webhooks` with `X-Github-Event: push`, `X-Hub-Signature` computed over the raw body using `attacker-org`'s `webhook_secret`, and a JSON body where `repository.owner.login == "attacker-org"` and `repository.full_name == "victim-org/victim-repo"`, `ref` set to victim's tracked branch (e.g. `refs/heads/master`), and `after` set to an attacker-chosen SHA.

Why existing guards fail: `drop_unhandled_event` only checks that a handler exists for the event type; `verify_signature`'s only anti-forgery check is HMAC validity against `repository_owner`'s own secret, which the attacker legitimately holds; `ExplicitParameters` schema in `PushHandler` only requires `ref` and `after` are present/typed, it does not constrain `repository.full_name` relative to `repository.owner.login`; there is no code anywhere that compares these two values.

### Impact Explanation
`GithubSyncJob#perform` loads the victim `Stack` by ID and calls `stack.github_commits`, which fetches commits through `stack.github_api` — this is scoped to the *stack's own repository owner* (via `Repository#github_app` → `Shipit.github(organization: owner)`), not the attacker's org, so the job fetches real commits from GitHub for the victim repo using Shipit's own installation credentials for `victim-org`. [6](#0-5) [7](#0-6) 

The forged webhook lets the attacker: (a) trigger an unauthenticated, repeatable forced resync of an arbitrary victim stack whenever they want, and (b) supply an `expected_head_sha` (`params.after`) that does not correspond to reality — if it happens to not exist yet in GitHub, this drives repeated retry/reschedule behavior (`GithubSyncJob` retry loop) for up to `MAX_RETRY_ATTEMPTS`. However, because `fetch_missing_commits` and `append_commit` still pull data exclusively from the real GitHub API using victim-org's legitimate installation token, the attacker cannot inject arbitrary commits, cannot forge commit data, and cannot cause a deploy — `CacheDeploySpecJob` and any deploy path require the commits to genuinely exist upstream on GitHub. The write achieved is limited to: enqueuing jobs against another tenant's stack ID, forcing a resync (which is idempotent with real state), and forcing accessibility-state churn (`mark_as_accessible!`/`mark_as_inaccessible!`) — not a forged deploy, rollback, merge, or credential exfiltration.

This is a real write to a resource (the victim stack) triggered by a payload authenticated under the wrong tenant's secret, matching the "payload for one repository mutating another's stack" category structurally, but the blast radius is bounded to sync/state churn rather than arbitrary code execution, credential leakage, or unauthorized deploy/rollback/merge, since the actual commit data still originates from GitHub via the correct per-repo installation credentials.

### Likelihood Explanation
Preconditions are realistic and attacker-achievable without any Shipit or victim secrets: the attacker only needs their own GitHub org with the Shipit GitHub App installed (which grants them their own legitimate `webhook_secret`), and must know or guess a victim `owner/repo` name that has an active Shipit `Stack` (repo names are often public/discoverable). No Shipit session, API token, or GitHub credentials for the victim are required. The request is trivially repeatable and can target any repository configured in Shipit, since nothing in `verify_signature` or `PushHandler` ties the payload's stated repository to the authenticated organization.

### Recommendation
In `WebhooksController#verify_signature`, additionally require that the resolved `repository_owner` matches the organization segment of `payload.dig('repository', 'full_name')` (and `organization.login` when present), rejecting the request with `422` on mismatch, before dispatching to any handler. Alternatively/additionally, in `Handler#stacks`, resolve the repository owner from the same trusted, signature-verified value used in `verify_signature` rather than re-deriving it from the unauthenticated `full_name` field in the payload.

### Proof of Concept
Minitest plan for `test/controllers/webhooks_controller_test.rb` (illustrative; would need to be written under `test/`):
```ruby
test "push payload signed by attacker-org but targeting victim-org/victim-repo enqueues job for victim stack" do
  victim_stack = shipit_stacks(:shipit) # repository owner/name = "victim-org/victim-repo"

  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    stub(verify_webhook_signature: true)
  )

  request.headers['X-Github-Event'] = 'push'
  payload = JSON.parse(payload(:push_master))
  payload['repository']['owner']['login'] = 'attacker-org'   # authenticates against attacker-org's secret
  payload['repository']['full_name'] = 'victim-org/victim-repo' # selects victim's stack
  payload['ref'] = 'refs/heads/master'
  expected_head_sha = payload['after']

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha:]) do
    post :create, body: payload.to_json, as: :json
  end
end
```
Assertions on both sides of the binding: before the request, `repository_owner` (`'attacker-org'`) ≠ organization segment of `repository.full_name` (`'victim-org'`); after processing, the test shows `GithubSyncJob` was enqueued with `victim_stack.id`, proving the mismatch was never checked and the wrong tenant's authentication was accepted to act on the victim's stack.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-26)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }
```

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
```
