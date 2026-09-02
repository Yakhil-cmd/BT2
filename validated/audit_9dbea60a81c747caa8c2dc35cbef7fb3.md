Confirmed: the vulnerable binding exists. `Handler#repository_name` (and thus `Handler#stacks`, used by `PushHandler#process`) is derived from `payload.dig('repository', 'full_name')` [1](#0-0) , which is a **completely independent** JSON field from the one used to select the HMAC secret for signature verification, `repository_owner` = `params.dig('repository', 'owner', 'login')` (or `params.dig('organization', 'login')`) in `WebhooksController#verify_signature` / `#repository_owner` [2](#0-1) .

### Title
Webhook signature is validated against the payload's `repository.owner.login`/`organization.login` while the push handler acts on the independent, unauthenticated `repository.full_name` field, allowing cross-organization stack sync forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based solely on `repository.owner.login` (falling back to `organization.login`) extracted from the JSON body [3](#0-2) [4](#0-3) . Once the signature check passes, `Handler#call` dispatches the whole payload to handlers such as `PushHandler`, which locates the target `Stack`s via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` [1](#0-0) [5](#0-4) . Because `repository.owner.login` and `repository.full_name` are two unrelated, attacker-supplied JSON strings in a self-crafted request body (this endpoint accepts a raw JSON payload signed only over its bytes, not validated against real GitHub repo metadata), nothing binds them to the same value.

### Finding Description
Shipit supports multiple GitHub organizations, each configured with its own `webhook_secret` in `config/secrets*.yml` (e.g. `somegithuborg`, `someothergithuborg`) [6](#0-5) , all funneling into a single shared `WebhooksController#create` endpoint [7](#0-6) .

To verify a webhook, the controller does:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end

def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end
``` [2](#0-1) 

`verify_webhook_signature` is a straight HMAC-SHA1 comparison of the *entire raw body* against `webhook_secret` for the org named by `repository_owner` [8](#0-7) . This proves only "this body was signed by the org whose name appears at `repository.owner.login`" — it does not constrain any other field inside that same body.

Once verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs the registered handlers with the full, attacker-controlled `params` hash [7](#0-6) . `PushHandler#process` resolves the target stacks strictly through `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [1](#0-0) 

`Repository.from_github_repo_name` simply splits this string on `/` and does a DB lookup by `owner`/`name` [5](#0-4) , with no cross-check that `owner` equals the `repository.owner.login`/`organization.login` value that was used to pick the signing secret.

This breaks the trust binding: **organization that authenticated (`repository.owner.login`) ≠ repository that is written (`repository.full_name`)**. An attacker who legitimately controls (or knows the `webhook_secret` of) *any one* configured GitHub organization in the multi-tenant Shipit instance — e.g. their own org `attacker-org`, which they registered/configured themselves — can craft a webhook body such as:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
Sign it with `attacker-org`'s known `webhook_secret`. `repository_owner` resolves to `attacker-org`, so `verify_signature` succeeds. But `PushHandler` then looks up stacks for `victim-org/victim-repo` and calls `stack.sync_github(expected_head_sha: params.after)` on them — forcing a resync toward an attacker-chosen SHA for a stack the attacker has no authorization over.

### Impact Explanation
This lets an attacker who only controls one tenant/org configured in a shared Shipit deployment trigger `GithubSyncJob`/`sync_github` on stacks belonging to a *different* organization's repository, forcing the head SHA tracked by that stack to an attacker-chosen value (`expected_head_sha: params.after`) without ever proving control of, or a valid signature scoped to, the victim organization/repository. This is a cross-repository/cross-tenant write of stack state driven purely by attacker-controlled JSON fields that escape the signature's binding, matching the "cross-repository writes" / unauthorized-deploy-adjacent impact category, since manipulated `last_deployed_sha`/HEAD tracking can subsequently influence deploy/rollback eligibility for the victim stack.

### Likelihood Explanation
Exploitability requires the attacker to control (or otherwise know the `webhook_secret` for) at least one organization configured in the same multi-tenant Shipit instance — a realistic scenario for any Shipit deployment serving multiple orgs/tenants (as the shipped `config/secrets.development.shopify.yml` template explicitly demonstrates with two independent org configs). No GitHub App private key, session, or `ApiClient` token is needed — only a webhook_secret belonging to any one configured org, which that org's own legitimate owner already possesses by design. This is a structural cross-tenant boundary failure, not a cryptographic break.

### Recommendation
In `WebhooksController`/`Handler`, enforce that every field used to select or act on a repository is validated against the *same* authenticated organization: after `verify_signature` succeeds for `repository_owner`, reject the payload (or scope `Repository.from_github_repo_name` lookups) unless `repository.full_name`'s owner segment case-insensitively equals `repository_owner`. Equivalently, have `Handler#repository_name` derive the owner solely from the already-authenticated `repository_owner`, rather than trusting the unrelated `repository.full_name` string.

### Proof of Concept
1. Configure a multi-tenant Shipit instance with two orgs, `attacker-org` (webhook_secret known to attacker, e.g., because the attacker legitimately owns/administers that org) and `victim-org` (has a Shipit `Stack` tracking `victim-org/victim-repo`).
2. Craft payload:
```json
{
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"},
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, raw_body)>` and POST to the shared `/webhooks` endpoint with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, verifies successfully against `attacker-org`'s secret [3](#0-2) .
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stacks [9](#0-8) , even though the signature never authenticated anything about `victim-org`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
