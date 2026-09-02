### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login` from the unverified payload, while handlers act on an unrelated `repository.full_name` (or, for status events, no repository scope at all) — allowing a party who controls one configured GitHub App's `webhook_secret` to forge events for a different organization's repositories - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/secret to verify a webhook against using `repository_owner`, a value read straight out of the *unverified* JSON body. The handlers that subsequently act on the payload (`app/models/shipit/webhooks/handlers/handler.rb`, `push_handler.rb`, `status_handler.rb`, `check_suite_handler.rb`, `pull_request/*_handler.rb`) resolve the target `Stack`/`Commit` from a different, independently-attacker-controlled field (`repository.full_name`, or for `status` events, a bare `sha` lookup with no repository scoping at all). Because these two fields are never cross-checked, whoever controls the `webhook_secret` for *any* GitHub organization configured on the Shipit instance can sign a payload as that organization while pointing the payload's `repository`/`sha` fields at a completely different organization's stacks or commits.

### Finding Description
`verify_signature` selects the app config to check the signature against using data taken from the raw, not-yet-authenticated request body: [1](#0-0) [2](#0-1) 

`repository_owner` comes from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). `Shipit.github(organization: repository_owner)` then looks up that organization's configured `webhook_secret` from `secrets.yml` (Shipit explicitly supports multiple independently-configured GitHub organizations, each with its own secret — see `docs/setup.md` "Using Multiple Github Applications"), and the signature is checked with `verify_webhook_signature` against that secret: [3](#0-2) 

Once the signature check passes, `params` (the entire attacker-supplied JSON, `repository.owner.login` included) is handed unchanged to the event handlers: [4](#0-3) 

Handlers resolve which `Stack`/`Repository` to act on from a *different* field, `repository.full_name`, with no check that it is consistent with `repository.owner.login`: [5](#0-4) 

`StatusHandler` is worse: it does not use `repository`/`stacks` scoping at all, it looks up commits globally by `sha` across the whole database and writes a status to every match: [6](#0-5) 

**Broken binding (equality that should hold but doesn't):**
`organization authenticated by verify_signature (repository.owner.login)` == `repository/commit actually mutated by the handler (repository.full_name / global sha lookup)`

Because the attacker fully controls the JSON body (both fields sit at the same trust level — they're both "not yet verified" until the HMAC check passes, and the HMAC check only binds the raw bytes to *a* secret, not to internal consistency between fields), an attacker who legitimately administers the GitHub App for Organization A (and therefore knows Organization A's `webhook_secret`, e.g. a customer/business unit sharing the same Shipit instance) can:
1. Set `repository.owner.login` (or `organization.login`) = `"OrgA"` so `verify_signature` selects and successfully validates against Org A's secret.
2. Set `repository.full_name` (push/check_suite/pull_request events) or `sha` (status events) to reference a stack/commit belonging to Org B, a different, unrelated organization also configured on the same Shipit installation.

### Impact Explanation
This breaks a cross-organization/cross-repository trust boundary that Shipit's multi-org configuration is explicitly designed to preserve (each org gets its own App/secret so that one org cannot act on another's behalf). Concretely:
- Via `StatusHandler`, an attacker can forge a passing (or failing) commit status for *any* commit in *any* stack on the instance, regardless of which repository/organization it belongs to, since the lookup is a global `Commit.where(sha: ...)` with no ownership check at all. Commit statuses are used by Shipit to gate deploy safety (CI/checks used for deployability), so this can be used to force an unsafe commit to appear deployable/mergeable in a repository the attacker has no legitimate access to — a cross-repository write with real deploy-safety consequences.
- Via `PushHandler`/`CheckSuiteHandler`/pull-request handlers, an attacker can trigger `stack.sync_github`, check-run refreshes, or review-stack archive/unarchive/labels for a Stack belonging to an organization they don't administer.

This matches "cross-repository writes / unauthorized deploy" (Critical) in the accepted impact list, since it lets an attacker who only controls their own org's webhook secret mutate deploy-relevant state (commit statuses, stacks) belonging to a different organization.

### Likelihood Explanation
Requires only that: (a) the Shipit instance is configured with more than one GitHub organization (an explicitly documented and supported configuration, see `docs/setup.md` "Using Multiple Github Applications"), and (b) the attacker has legitimate knowledge of one org's own `webhook_secret` (e.g., they are that org's own GitHub App admin) while wanting to affect a different org's stacks on the same shared Shipit instance. No GitHub App private key, `api_clients_secret`, or Shipit session is needed — only the webhook secret of any one of the configured organizations, which the rules treat as available to that organization's own operators, not as a global-trust credential across other organizations.

### Recommendation
After a valid signature is verified for organization `O`, re-derive/validate every organization-identifying field used downstream (`repository.owner.login`, `organization.login`, and — critically — the owner portion of `repository.full_name`) and reject the webhook (422) if they disagree with `O`. Additionally, `StatusHandler#process` should scope its `Commit` lookup through `stacks`/`repository_name` (as the base `Handler` already supports) instead of a bare, repository-unscoped `Commit.where(sha: ...)`.

### Proof of Concept
1. Shipit is configured for two orgs in `secrets.yml`: `OrgA` (attacker-administered, secret known to attacker) and `OrgB` (victim, tracked stacks on the same instance).
2. Attacker crafts a `status` event body:
```json
{
  "sha": "<sha of a commit belonging to an OrgB-owned stack>",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/irrelevant-repo" }
}
```
3. Attacker signs the raw body with `OrgA`'s known `webhook_secret` and sends it to `POST /webhooks` with `X-Github-Event: status` and the resulting `X-Hub-Signature`.
4. `WebhooksController#verify_signature` computes `repository_owner = "OrgA"`, loads `OrgA`'s app, and `verify_webhook_signature` succeeds because the attacker signed with the correct (their own) secret [7](#0-6) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the OrgB commit regardless of the `repository` field — and calls `create_status_from_github!`, writing a forged status onto OrgB's commit [6](#0-5) , even though the attacker never possessed OrgB's `webhook_secret`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
