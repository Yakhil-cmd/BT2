### Title
Webhook signature is verified against the payload's `repository.owner`/`organization` while handlers act on the unrelated `repository.full_name` / bare commit `sha`, allowing cross-organization forgery of commit statuses and repository sync events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the incoming HMAC against using `repository_owner`, taken from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`). But once the signature check passes, every downstream handler (`Handler#repository_name`, `PushHandler`, and especially `StatusHandler`) reads a *different* field of the same JSON body — `repository.full_name`, or in `StatusHandler`'s case nothing about the repository at all, just the bare `sha` — to decide what to act on. Nothing re-derives or cross-checks that the org used to pick the secret actually matches the repository/commit that is mutated. This is the same class of bug as the Oracle report: a value is authenticated/validated ("`repository.owner.login` maps to a trusted secret"), but a *different, unchecked* value from the same message ("`repository.full_name`"/`sha`") is what is actually consumed downstream.

### Finding Description [1](#0-0)  verifies the signature using a secret looked up by `repository_owner`: [2](#0-1) 

The secret itself is per-organization, as shown by `GithubApp#verify_webhook_signature`, which HMACs the *entire* raw body with the secret configured for that specific organization: [3](#0-2) 

Shipit is explicitly designed to be shared across multiple, mutually-independent GitHub organizations, each with its own `webhook_secret`: [4](#0-3) 

Since HMAC verification only guarantees the body was signed by *whichever* org's secret was selected — not that the body's contents pertain to that org — an attacker who is the legitimate owner/admin of one org's GitHub App on this shared instance (call it `attacker-org`, with a `webhook_secret` they know) can compute a valid signature over an arbitrary payload whose `repository.owner.login` (or `organization.login`) is `"attacker-org"`, while embedding a completely different `repository.full_name` (or bare `sha`) belonging to a victim organization.

Downstream, `Handler#repository_name` binds only to `repository.full_name`, ignoring `repository.owner`: [5](#0-4) 

`PushHandler` uses that to look up stacks and trigger a sync with an attacker-chosen `expected_head_sha`: [6](#0-5) 

Worse, `StatusHandler` doesn't scope by repository at all — it matches purely on the global `sha` column across the entire `Commit` table: [7](#0-6) 

So an attacker who only controls `attacker-org`'s webhook secret can forge a `status` event that sets `state: "success"` (with arbitrary `description`/`target_url`/`context`) on **any commit sha in any repository/stack tracked by the shared Shipit instance**, including ones belonging to organizations the attacker has no relationship with.

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by verify_signature (repository_owner)` == `repository/commit actually mutated by the handler (repository.full_name / bare sha)`

Before the attack, GitHub always sends these two facts consistently (the same repository object). After the attacker's forged POST, they diverge: the org used to select/verify the secret is `attacker-org`, but the entity written is a victim stack's commit or repository sync state.

### Impact Explanation
This is a cross-repository/cross-organization write achieved without any Shipit session, `ApiClient` token, or the victim org's `webhook_secret`/`api_clients_secret` — only knowledge of a secret the attacker legitimately possesses for their own, unrelated org registered on the same Shipit instance. Concretely:
- `StatusHandler` lets the attacker forge a `success` CI status on a victim's pending commit. Since deploy eligibility gating in Shipit typically depends on required commit statuses being green, this can directly enable an **unauthorized deploy** of a commit that hadn't actually passed CI/review.
- `PushHandler` lets the attacker force a `GithubSyncJob` for a victim stack with an attacker-chosen `expected_head_sha`, causing the victim stack to fetch and ingest commits reachable from that SHA using the victim's own `github_access_token`/App credentials, effectively an unauthorized manipulation of the victim's deployable commit history.

Both qualify as Critical under the rules ("cross-repository writes, or an unauthorized deploy").

### Likelihood Explanation
Requires only that the attacker be a legitimate administrator of any single GitHub organization configured on the same, shared, multi-tenant Shipit deployment (a supported and documented configuration per `docs/setup.md` and the multi-org example in `config/secrets.development.shopify.yml`). They never need write access, a session, or any credential belonging to the victim org — only their own org's `webhook_secret`, which they hold legitimately. Crafting the raw JSON body and its HMAC is trivial once the secret is known.

### Recommendation
Bind the org used for signature verification to the same identifier consumed by every downstream handler, and re-validate it in each handler:
- In `WebhooksController`, after selecting `repository_owner` for secret lookup, verify that `params.dig('repository','full_name')` (when present) is actually owned by `repository_owner` before dispatching to handlers.
- In `Handler#repository_name`/`PushHandler`/pull-request handlers, look up the `Repository` and confirm its `owner`/organization matches the organization whose secret validated the request.
- In `StatusHandler`, scope the `Commit` lookup by the tracked `Repository`/`Stack` derived from the verified organization, not by a bare, globally-unique `sha` match.

### Proof of Concept
1. Attacker is the owner of `attacker-org`, which has its own GitHub App registered on the shared Shipit instance with a known `webhook_secret`.
2. Attacker crafts:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "description": "forged",
  "context": "ci/required-check",
  "target_url": "https://attacker.example.com",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `sha1=HMAC-SHA1(attacker-org_webhook_secret, raw_body)` and sends it as `X-Hub-Signature`, with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` to `"attacker-org"` [2](#0-1) , fetches `attacker-org`'s `GithubApp`, and the HMAC check succeeds because the attacker used the correct (their own) secret.
5. `StatusHandler#process` then matches `Commit.where(sha: params.sha)` — the victim's commit — and calls `create_status_from_github!`, marking it as passing CI, even though `attacker-org` has no relationship to `victim-org/victim-repo`. [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
