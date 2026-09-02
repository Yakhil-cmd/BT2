### Title
Webhook signature verified against one GitHub organization while the acted-upon commit/repository is taken from unauthenticated payload fields, allowing cross-organization commit status forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` picks the `GithubApp`/`webhook_secret` to validate the HMAC signature based on `repository_owner`, a value read straight out of the *same* unauthenticated JSON body it is about to validate. Nothing cryptographically binds that "authenticating organization" to the repository/commit the handler subsequently mutates: `StatusHandler` looks up commits globally by `sha` with **no repository scoping at all**. An operator who legitimately owns any single GitHub organization onboarded to this Shipit instance (and therefore knows that org's `webhook_secret`) can forge a `status` webhook that produces a valid signature for their own org, while the payload's `sha`/`state`/`context` target a commit that belongs to a completely different, victim organization's stack.

### Finding Description
`verify_signature` computes the org used for signature verification from the payload itself: [1](#0-0) [2](#0-1) 

The secret used is per-organization, resolved via `Shipit.github(organization: repository_owner)` and checked with `verify_webhook_signature`, which HMACs the raw body with that organization's own `webhook_secret`: [3](#0-2) 

This only proves the sender knows the secret for whatever organization login is embedded in the payload — it proves nothing about which repository or commit the rest of the payload refers to, because `repository.owner.login` and `repository.full_name`'s owner segment are two independent attacker-controlled strings in the same signed blob and are never checked for equality.

Handlers derive the target repository from a *different* field, `repository.full_name`: [4](#0-3) 

`StatusHandler` doesn't even use that `repository_name`/`stacks` scoping helper — it resolves the affected `Commit` purely by `sha`, globally, across every repository tracked by the Shipit instance: [5](#0-4) 

So the equality that should hold — "organization whose secret authenticated the request" == "repository/commit the handler writes to" — is never enforced. An attacker who legitimately administers `attacker-org` (onboarded to this Shipit instance with its own `webhook_secret`) can:
1. Set `repository.owner.login` (or `organization.login`) = `attacker-org` so `verify_signature` selects and successfully validates against `attacker-org`'s secret.
2. Set `sha`, `state`, `context` (and other `StatusHandler` params) to target a commit belonging to `victim-org`'s stack.

The signature check passes, and `StatusHandler#process` applies the forged status to the victim's commit via `commit.create_status_from_github!(params)` with no ownership check whatsoever.

### Impact Explanation
Commit statuses are used by Shipit to gate CI-based deploy/merge readiness (required checks, merge queue eligibility, deployable status). An attacker who controls a single onboarded organization can forge arbitrary "success" statuses (matching a required CI context) on commits belonging to an unrelated victim organization's repository, letting Shipit treat unreviewed/unvetted code as CI-green and become eligible for automated merge/deploy. This is an authentication-bypass-class issue: the credential presented (attacker-org's webhook secret) does not authorize the action actually performed (writing CI state for victim-org's commit), enabling an unauthorized merge/deploy decision to be influenced.

### Likelihood Explanation
Exploitation requires only that the attacker legitimately controls one organization already onboarded to the same Shipit instance (knows that org's `webhook_secret`, which is standard for any operator wiring up their own GitHub App/organization) — no repository write access, GitHub App private key, or Shipit session/API token is required to hit `WebhooksController#create`, which is an unauthenticated public endpoint gated only by `verify_signature`. Multi-tenant Shipit deployments (multiple orgs configured in `config/secrets*.yml` under `github:`) are explicitly supported, as seen in `config/secrets.development.shopify.yml`, making this a realistic likelihood scenario.

### Recommendation
Bind the verified identity to the acted-upon resource: after verifying the signature against `repository_owner`, require that `payload.dig('repository', 'full_name')`'s owner segment (and, in `StatusHandler`, the commit's repository) matches the same `repository_owner`/organization used for signature verification. Reject the webhook (422) if they diverge, and update `StatusHandler` (and any other handler that queries by a bare identifier like `sha`) to scope its lookup through `Repository.from_github_repo_name(repository_name)` / `stacks` rather than querying `Commit` globally.

### Proof of Concept
1. Attacker legitimately administers `attacker-org`, onboarded to the shared Shipit instance with `webhook_secret = S`.
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim-org/victim-repo commit sha, e.g. queued for merge/deploy>",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "https://ci.example.com/fake",
  "repository": { "full_name": "attacker-org/whatever", "owner": { "login": "attacker-org" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S, body)` using `attacker-org`'s known secret, matching `Hook::DeliverySigner`/`verify_webhook_signature` semantics: [3](#0-2) 
4. POSTs to `/webhooks` with `X-Github-Event: status`. `verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s `GithubApp`, and the signature validates successfully: [1](#0-0) 
5. `StatusHandler#process` executes `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no relation to `attacker-org`, writing a forged "success" status onto the victim's commit: [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
