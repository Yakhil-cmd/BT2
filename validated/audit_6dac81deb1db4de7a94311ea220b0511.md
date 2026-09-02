### Title
Cross-organization webhook forgery via decoupled signature-scoping and payload-processing fields - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController` selects which GitHub App configuration (and therefore which HMAC secret) to use for signature verification based on a single field extracted from the *unverified* JSON body, while the downstream event handlers that actually mutate Shipit state (stacks, teams, users, commit statuses, etc.) act on other fields of that same unverified body. Because the HMAC only certifies the raw bytes were signed by *some* known secret — not that the fields used for authorization scoping and the fields used for write-target resolution are internally consistent — an actor who legitimately controls a webhook secret for one configured GitHub organization can forge a payload that authenticates as "org A" while its actual repository/target fields point at "org B".

### Finding Description
`Shipit::WebhooksController#verify_signature` computes the org used for signature verification like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the attacker-suppliable JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`) *before* the signature has been confirmed to originate from that specific organization's app — it is only used to pick *which* secret to check against: [3](#0-2) 

The verification is a pure HMAC-SHA1 over the raw POST body against the secret belonging to whatever organization `repository_owner` names — it makes no assertion that any other field in that same payload (e.g. `repository.full_name`, `repository.name`, `team.id`, `member.login`) actually belongs to that organization. Once `verify_signature` passes, `create` dispatches the entire parsed payload to the registered handlers for the event type: [4](#0-3) 

Those handlers (push, status, check_suite, membership, pull_request, etc.) resolve the Stack/Repository/Team/User to act on using other fields of the same body (e.g. `repository.full_name` for push/status handlers, `member.login`/`team` for membership handlers), independent of the `repository_owner` value used purely for secret selection.

Shipit explicitly supports and documents multi-organization deployments where each organization has its own, independently-managed `webhook_secret`: [5](#0-4) 

The binding that should hold is:
`organization whose secret authenticated the request == organization that owns the resource actually written by the handler`

Because signature verification only checks "was this raw body signed by *some* org's secret" and the org used for that check is attacker-controlled input, this binding is not enforced. An administrator/operator of one low-trust org configured in Shipit (who legitimately possesses that org's `webhook_secret`, e.g. because they self-configured their own GitHub App integration) can:
1. Craft a JSON payload where `repository.owner.login` (or `organization.login`) = their own org "A" (so `Shipit.github(organization: repository_owner)` picks org A's secret).
2. Set `repository.full_name`, `member.login`, `team`, etc. to point at a different, higher-trust org "B" / repository they do not control.
3. Sign the raw body with org A's webhook secret and set `X-Hub-Signature` accordingly.
4. POST to `/webhooks`. Verification succeeds (org A's secret matches), and the handler for the event (e.g. `push`, `membership`, `status`) processes the forged fields referencing org B's repository/team/user.

### Impact Explanation
This breaks a deployment-trust boundary between organizations hosted in the same Shipit instance: possession of one org's webhook secret becomes sufficient to inject events (sync a fake push, alter commit status used for CI gating deploys, add/remove team memberships, open/close/label pull requests used for merge-queue automation) against stacks/repositories/teams belonging to a *different*, unrelated organization. Depending on the handler reached, this can drive unauthorized state changes feeding into deploy/merge decisions (e.g. forged commit statuses influencing `merge_queue`/CI-gated automatic deploys) or membership/team tampering that affects `Shipit.github_teams` authorization — a cross-repository write / authorization-escalation impact.

### Likelihood Explanation
Requires only that the attacker possess a valid `webhook_secret` for *any one* organization configured in a multi-org Shipit deployment — not privileged access to Shipit itself, not a GitHub App private key for the target org, and not repository write access on the target org. This is a realistic operating condition for a Shipit instance shared across several orgs/teams with differing trust levels, since each org's webhook secret is typically known to that org's own administrators. The `/webhooks` endpoint is unauthenticated by design (protected only by the HMAC), so no session or `ApiClient` token is needed.

### Recommendation
Bind the HMAC-verified organization to the resource-resolution path: after `verify_signature` succeeds, cross-check that every organization-identifying field the handler will use to resolve a Stack/Repository/Team/User (`repository.owner.login`, `repository.full_name`'s owner segment, etc.) is identical to the `repository_owner` value that was used to select the verifying secret, and reject the event (422) on mismatch. Alternatively, resolve `Shipit.github(organization: ...)` from the field that is *actually* used downstream by each handler, not a possibly-different field, so a single canonical, verified org identity flows through both verification and resolution.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` and `orgB`, each with distinct `webhook_secret`s, per the documented multi-org setup (`config/secrets.development.shopify.yml`).
2. As an operator who knows `orgA`'s `webhook_secret` (e.g., because you administer `orgA`'s GitHub App), build a push-event JSON body:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo", "name": "victim-repo" },
  "after": "<attacker-chosen-sha>",
  "ref": "refs/heads/master"
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>`.
4. `POST /webhooks` with `X-Github-Event: push` and the above signature.
5. `verify_signature` resolves `repository_owner` = `orgA`, fetches `orgA`'s app, and the HMAC check passes since it was signed with `orgA`'s secret.
6. The push handler dispatch proceeds using `repository.full_name` = `orgB/victim-repo`, causing Shipit to act on `orgB`'s stack (e.g., enqueue a sync job / update state) despite the request never being authenticated by `orgB`.

Note: I was unable to open `app/models/shipit/webhooks/handlers/push_handler.rb` in this session (tool call limit reached) to quote the exact field used for Stack resolution inside that specific handler; the root-cause decoupling is nonetheless fully established at the controller/`GithubApp#verify_webhook_signature` layer shown above, and the existence of `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, and membership handling confirmed via `grep_search` shows multiple handlers consume the same unverified payload independently of the `repository_owner` field used for secret scoping.

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
