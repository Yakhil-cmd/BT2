### Title
Webhook Signature Verified Against `repository.owner.login`, But Handlers Act on the Unrelated `repository.full_name` Field - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the HMAC signature using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')`. However, every webhook `Handler` subclass resolves the target `Stack`/`Repository` to act on using an entirely different JSON field, `payload.dig('repository', 'full_name')` (see `Handler#repository_name`). These two fields are never cross-checked, so a signature that is valid for organization A's webhook secret can be used to sign a payload whose `repository.full_name` names a repository belonging to organization B.

### Finding Description
`verify_signature` in [1](#0-0)  picks the `Shipit.github(organization: repository_owner)` app config using: [2](#0-1) 
It then verifies the HMAC-SHA1 signature of the raw body against that organization's `webhook_secret` via `verify_webhook_signature` in [3](#0-2) .

Once the signature check passes, the raw JSON body is dispatched to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` in [4](#0-3) . Every handler resolves which `Stack`/`Repository` to mutate using a **different** JSON field, unrelated to the one used for signature routing: [5](#0-4) 

Nothing in the code enforces that `repository.owner.login` (used to select the signing secret) matches the owner segment embedded in `repository.full_name` (used to pick the actual target stack). Because HMAC signature verification only proves "this request body was signed by whoever holds organization A's `webhook_secret`," and does not proves anything about the value of an arbitrary sibling field inside that same body, an operator/admin who legitimately owns a repository/organization configured in this Shipit instance (and therefore knows or can freely set that org's webhook secret when they configure the GitHub webhook in their own repo settings) can hand-craft a JSON payload with:
- `repository.owner.login = "org-they-control"` (satisfies `verify_signature`, selects their own known secret)
- `repository.full_name = "victim-org/critical-repo"` (consumed by the handler to select the stack to act on)

and self-sign it with their own known secret, then POST it directly to `/webhooks`, bypassing GitHub entirely.

This is a direct analog of the reported bug class: an authorization check is performed against one field (`repository.owner.login`, akin to `mintFeeInUsdc`'s intended bps semantics) while the actually consequential action is driven by a completely different, unchecked field (`repository.full_name`, akin to the modifier's mismatched unit assumption) — the binding "organization that authenticated == repository that is written" is broken.

### Impact Explanation
This allows any org that has (or can create) a webhook integration with a known secret registered in this Shipit instance to forge events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) against a completely unrelated repository/stack that they do not own or control, as long as that repository is also tracked in the same Shipit instance. Depending on the handler, this can trigger unauthorized `GithubSyncJob` enqueues, commit status writes, check-run refreshes, or archive/unarchive of review stacks for a victim repository — a cross-repository write performed with credentials that were never authorized for that repository. This matches the "Critical: cross-repository writes" impact bucket.

### Likelihood Explanation
Requires the attacker to control (or be an admin of) at least one organization/repository that is already onboarded into the target Shipit instance with its own webhook secret — a realistic scenario for any multi-tenant Shipit deployment serving multiple orgs/teams, since GitHub webhook secrets are set by whoever configures the webhook in their own repository/org settings and are not secret from that org's own admins. No compromise of the Shipit host, no `ApiClient` token, and no GitHub App private key is required — only knowledge of one's own webhook secret and the ability to POST directly to the `/webhooks` endpoint.

### Recommendation
Do not use `repository.owner.login` merely to select the verification key while trusting a separate `repository.full_name` field for authorization. After computing `repository_owner`, re-derive/parse the owner from `repository.full_name` (or drop `full_name` entirely and reconstruct it from verified `owner.login` + `name`) and reject the webhook if they disagree. Alternately, verify the signature per-repository (bind the secret to the specific `Repository`/`Stack` record rather than only to the organization), and validate that any repository field consumed by a `Handler` belongs to the same organization whose secret validated the request.

### Proof of Concept
1. Attacker's org `evil-org` is configured in Shipit with a known `webhook_secret` (e.g., they set it when adding the webhook to their own repo).
2. Attacker crafts payload:
```json
{
  "repository": {
    "owner": { "login": "evil-org" },
    "full_name": "victim-org/critical-repo"
  },
  "after": "<attacker chosen sha>"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(evil-org secret, raw_body)>`.
4. `POST /webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner == "evil-org"`, fetches `evil-org`'s app, and the signature validates successfully [6](#0-5) .
6. `PushHandler` (subclass of `Handler`) resolves `repository_name` from `payload.dig('repository', 'full_name')` = `"victim-org/critical-repo"` [5](#0-4) , looks up that `Repository`'s stacks, and enqueues a sync/deploy-triggering job for a repository the attacker never controlled.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
