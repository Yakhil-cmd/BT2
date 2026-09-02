### Title
Cross-organization webhook forgery: `X-Hub-Signature` is verified against the org named in `repository.owner.login`, while the resource acted on is looked up via the unrelated `repository.full_name` field — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to verify the HMAC signature against based on `params.dig('repository', 'owner', 'login')` (or `organization.login`), a field taken from the same untrusted JSON body that the signature is supposed to protect. Every event handler, however, resolves the actual repository/stack to mutate using a *different* field of the same body: `payload.dig('repository', 'full_name')`. Because a single HMAC only proves "this body was sent by whoever holds the secret associated with the `owner.login` field", it does not bind `owner.login` to `full_name`. An attacker who controls (and thus knows the `webhook_secret` of) any one organization configured on a shared/multi-tenant Shipit instance can forge a payload where `repository.owner.login` names their own org (to pass signature verification) while `repository.full_name` names a victim organization's repository, causing the victim's stack to be mutated.

### Finding Description
- Signature verification: `WebhooksController#verify_signature` picks the GitHub App config to verify against using `repository_owner`: [1](#0-0) [2](#0-1) 

- The `GitHubApp` verifies the HMAC using the secret configured for that org only: [3](#0-2) 

- The Shipit instance can host multiple orgs, each with its own independent `webhook_secret`, as documented/configured: [4](#0-3) 

- Once the signature passes, `create` dispatches the raw, still-untrusted `params` to handlers: [5](#0-4) 

- Every handler resolves the target `Repository`/stack using a *different* field, `repository.full_name`, not `repository.owner.login`: [6](#0-5) [7](#0-6) 

- For example, `PushHandler` uses that repository's stacks to trigger a GitHub sync with an attacker-supplied SHA: [8](#0-7) 

The binding that should hold is: `organization whose secret authenticated the request == owner of the repository being written to`. Because `verify_signature` derives the org solely from `repository.owner.login` while the handlers act on `repository.full_name`, this equality is never enforced — the two fields live in the same attacker-controlled JSON body and can be set independently. An attacker who is a legitimate GitHub App owner/admin for "org-A" (and therefore knows org-A's `webhook_secret`) can post directly to `/webhooks` with `repository.owner.login = "org-A"` (so the signature check passes) and `repository.full_name = "org-B/victim-repo"` (so the handler acts on org-B's stack).

### Impact Explanation
This breaks the deployment-trust binding "organization authenticated vs. repository written" from an unprivileged-attacker's perspective relative to the victim org: an actor with no privileges on `org-B` can trigger stack mutations belonging to `org-B` merely by controlling `org-A`'s webhook secret on the same shared Shipit instance. Depending on handler, this can:
- Force a `GithubSyncJob`/deploy pipeline resync of a victim stack with an attacker-chosen `expected_head_sha` via `PushHandler`.
- Archive/unarchive review stacks or close pull requests belonging to a victim repository via the `pull_request/*` handlers, all of which resolve the target repo from `repository.full_name` only.

This is a cross-repository/cross-organization write performed under someone else's org identity that was never actually authenticated for that org, matching the "cross-repository writes / unauthorized deploy" impact class.

### Likelihood Explanation
Exploitability requires the attacker to control (know the webhook secret of) at least one organization configured on the same multi-tenant Shipit deployment — a realistic and explicitly supported configuration shape in this engine (multiple orgs each with independent `webhook_secret`, as shown in `config/secrets.development.shopify.yml`). No GitHub write access, Shipit session, or `ApiClient` token is needed; the attacker sends a raw HTTP POST directly to the public `/webhooks` endpoint with a manually computed HMAC using their own known secret.

### Recommendation
Bind the verified organization to the mutated resource: after `verify_signature` succeeds, re-derive `repository_owner` and compare it (case-insensitively) against the owner segment of `repository.full_name` (or `organization.login` for org-scoped events) before dispatching to handlers, rejecting the event with 422 on mismatch. Alternatively, pass the already-verified `repository_owner` into the handler layer and have `Handler#repository_name`/`Repository.from_github_repo_name` refuse to resolve a repository whose owner differs from it.

### Proof of Concept
1. Configure two orgs on one Shipit instance, e.g. `org-A` (secret `SECRET_A`, attacker-controlled) and `org-B` (victim, has a stack tracking `org-B/victim-repo`).
2. Attacker builds a forged push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "org-A" },
    "full_name": "org-B/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(SECRET_A, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "org-A")` and verifies successfully against `SECRET_A` [1](#0-0) .
5. `create` dispatches to `PushHandler`, which resolves stacks via `repository.full_name = "org-B/victim-repo"` [6](#0-5)  and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on org-B's stack [8](#0-7) , even though only `org-A`'s secret was ever validated.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

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
