### Title
Webhook signature verification is scoped to the payload's `repository.owner.login`, but handlers act on the independent, unauthenticated `repository.full_name` field, letting one authorized GitHub organization forge events for another organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate an inbound webhook's HMAC against using `repository_owner`, a value read straight out of the (still-unverified) JSON body [1](#0-0) . Every webhook handler, however, resolves the target `Stack`/`Repository` from an entirely different field in that same body, `repository.full_name` [2](#0-1) . Because the HMAC only proves "this byte string was signed with organization X's secret" and does not bind `repository.owner.login` to `repository.full_name`, an attacker who legitimately controls a webhook secret for one Shipit-tracked GitHub organization can forge a payload whose `owner.login` matches their own organization (so signature verification passes) while `full_name` points at a stack belonging to a completely different, more privileged organization also configured on the same Shipit instance.

### Finding Description
Shipit is explicitly designed to be multi-tenant across GitHub organizations: the secrets format keys multiple orgs, each with its own `webhook_secret`, `app_id`, and `private_key`, all hitting the same `/github/webhooks` endpoint [3](#0-2) . `GithubApp#verify_webhook_signature` correctly HMACs the *raw* request body against the secret of whichever org config was looked up [4](#0-3) , but the org used for that lookup is derived from attacker-controlled JSON, not anything cryptographically fixed:

```ruby
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`verify_signature` then does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [5](#0-4) 

This only proves the request was signed by whatever org's secret matches the `owner.login` the attacker chose to put in the body. Once verification passes, `create` dispatches the full parsed body to handlers [6](#0-5) , and every handler resolves its target repository independently via:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

Because `owner.login` and `full_name` are two independent strings inside the same attacker-supplied JSON body, nothing forces `full_name` to belong to the organization that actually signed the request. The equality that should hold - **organization that authenticated == repository that is written** - is broken: verification authenticates org A (via `owner.login`), but the handler code writes state for whatever repository `full_name` names, which can belong to org B.

### Impact Explanation
An attacker who controls (or has previously been granted) a webhook secret for *any* GitHub organization configured on the shared Shipit instance can forge signed webhook deliveries whose `repository.full_name` targets a stack owned by a different, more privileged organization on the same instance. Depending on handler, this enables:
- Forging `status` events to post arbitrary commit statuses (state/context/target_url) for commits on a victim stack [7](#0-6) , which can satisfy a stack's `ci.require` gate and let continuous deployment proceed on unreviewed/malicious code — an unauthorized deploy.
- Forging `push` events to trigger `GithubSyncJob` against the victim's stack, forcing Shipit to sync/attach GitHub-reported commits and invalidate/rewrite deploy history for a repository the attacker does not control [8](#0-7) .
- Forging `pull_request`/`membership` events to create stacks, users, or team memberships tied to the victim repository [9](#0-8) .

This is a cross-organization/cross-repository write achieved purely by holding valid credentials for an unrelated, lower-privileged organization also hosted on the instance — squarely in the "cross-repository writes / unauthorized deploy" Critical impact bucket.

### Likelihood Explanation
Exploitability requires only: (1) the Shipit instance be configured to track more than one GitHub organization (a documented, first-class configuration shown in `config/secrets.development.shopify.yml`), and (2) the attacker possess a legitimate webhook secret for any one of those tracked organizations (e.g., their own repo/org that an admin separately onboarded). No GitHub App private key, session, or `ApiClient` token is required — only the ability to sign an HTTP POST body with a secret the attacker legitimately holds for their own org. Given multi-org Shipit deployments are an intended use case, likelihood is realistic wherever more than one organization shares a Shipit instance.

### Recommendation
Bind the verified signature to the specific repository being acted upon, not merely to an organization name pulled from the unverified body. Concretely:
- After verifying the signature for `repository_owner`, additionally assert that `repository.full_name`'s owner segment equals the same `repository_owner`/organization that authenticated the request, rejecting the webhook otherwise.
- Alternatively, look up the target `Repository` first, resolve which organization *owns that repository* from trusted, pre-configured data (not from the payload), and verify the signature against that organization's secret rather than trusting `owner.login` from the JSON body to pick the verification key.

### Proof of Concept
Given a Shipit instance configured with two organizations, `attacker-org` (secret `S1`, attacker-controlled) and `victim-org` (secret `S2`, hosts a tracked, continuously-deployed stack), the attacker:

1. Crafts a payload:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/production" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "https://attacker.example.com"
}
```
2. Computes `X-Hub-Signature: sha1=HMAC-SHA1(S1, body)` using their own `attacker-org` secret.
3. Sends `POST /github/webhooks` with `X-Github-Event: status`.
4. `verify_signature` looks up `Shipit.github(organization: "attacker-org")` (matches `repository_owner` from the body), verifies successfully against `S1` [5](#0-4) .
5. The `status` handler resolves the target using `repository.full_name` = `"victim-org/production"` [10](#0-9) , and a `Status` record is created for the victim's commit, potentially unblocking `ci.require` and triggering an automatic deploy on `victim-org/production` — despite the request never being signed by `victim-org`'s secret.

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

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-41)
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
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L38-42)
```ruby
          test "creates stacks for repos that are tracked" do
            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload_parsed(:pull_request_opened)).process
            end
          end
```
