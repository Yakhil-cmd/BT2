### Title
Webhook signature verification keyed off an attacker-controlled organization field, decoupled from the repository actually acted upon - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub App (and thus which `webhook_secret`) to validate an inbound webhook against using a field taken directly from the *unverified* JSON body, while the handlers dispatched afterwards act on repository/stack identifiers taken from that same unverified body. When any configured GitHub App/organization has no `webhook_secret` set (an explicitly supported, documented configuration), an unauthenticated caller can forge a payload that is "verified" against that secret-less organization while its repository/stack fields actually reference a different, properly-secured organization's stack — breaking the binding `organization authenticated == organization/repository written`.

### Finding Description
`verify_signature` derives the org used for verification purely from the request body: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — fields inside the raw, not-yet-verified JSON POST body. This value selects which `GithubApp` config (and secret) is used:

`Shipit.github(organization: repository_owner)`.

The actual signature check then short-circuits to "verified" whenever that particular organization's config has no `webhook_secret` configured: [3](#0-2) 

`webhook_secret` being unset is a documented, supported state ("Webhook secret (optional)"), and multi-organization installations are explicitly supported via per-organization keys in `secrets.yml`: [4](#0-3) 

The test fixtures for multi-app setups show this exact scenario is exercised in the codebase — a second organization configured with `webhook_secret: # nil`: [5](#0-4) 

Because `repository_owner` (used only to pick the verification secret) and the repository/stack-identifying fields consumed later by `Shipit::Webhooks` handlers (e.g. `repository.full_name`, `sha`, branch, etc., all still inside the same attacker-supplied JSON body) are never cross-checked against each other, an attacker can set `repository.owner.login`/`organization.login` to an org with no `webhook_secret` (so `verify_webhook_signature` returns `true` unconditionally, `X-Hub-Signature` value irrelevant) while setting the rest of the payload (`repository.full_name`, commit SHAs, statuses, PR data) to target a stack that actually belongs to a different, secret-protected organization. The `create` action then dispatches the forged payload unmodified to all matching handlers: [6](#0-5) 

This breaks the binding: **organization used to authenticate the webhook == organization whose repository/stack state is mutated**. Before the attack, for genuine GitHub-signed payloads these two are always the same org, so the binding trivially holds. After a crafted request, verification passes against org A (no secret) while the mutated stack belongs to org B (has a secret the attacker never possessed).

### Impact Explanation
Webhook handlers drive state that affects deploy/merge decisions and stack synchronization — e.g. `push` events enqueue `GithubSyncJob`, `status`/`check_suite` events create `Status`/check-run records consumed by CI gating and the merge queue, and `pull_request`/`membership` events mutate `MergeRequest`/`Team`/`Membership` records. An attacker who never possessed the target organization's real webhook secret can inject forged CI status, sync state, or merge-queue-relevant events for that organization's stacks, as long as *any* other configured organization on the same Shipit instance lacks a `webhook_secret`. This can influence which commits appear "green" for continuous deployment/merge, i.e. an unauthorized deploy/merge influence — Critical-adjacent impact per the rubric ("unauthorized deploy, rollback or merge").

### Likelihood Explanation
High in any multi-tenant Shipit deployment where at least one configured GitHub App organization omits `webhook_secret` (explicitly documented as optional and exercised in the codebase's own multi-app fixtures). No credentials, session, `ApiClient` token, or GitHub App private key are required — only an unauthenticated POST to the public `/webhooks` endpoint with a crafted JSON body.

### Recommendation
Verify the webhook signature using the organization/app config that corresponds to the actual `repository.full_name` being mutated (i.e., resolve the target `Stack`/`Repository` model first, then verify against that repository's known configured organization), and reject requests where the two disagree. Additionally, treat a missing `webhook_secret` as "signature check not applicable" only when there is exactly one configured GitHub App, or require a `webhook_secret` whenever more than one organization is configured, closing the "always verified" short-circuit for multi-org deployments.

### Proof of Concept
1. Configure Shipit with two GitHub App organizations per `secrets.yml`: `OrgA` (no `webhook_secret`) and `OrgB` (has a real `webhook_secret`, and owns a tracked `Stack`/`Repository` in Shipit).
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and a body such as:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" },
  "after": "<attacker chosen sha already known/pushed to OrgB/target-repo>",
  "ref": "refs/heads/main"
}
```
Any (or no) `X-Hub-Signature` value.
3. `verify_signature` calls `Shipit.github(organization: "OrgA")`; since `OrgA` has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally, regardless of the signature header.
4. `create` proceeds and dispatches the payload; the `push` handler resolves the stack via `repository.full_name` = `OrgB/target-repo`, enqueuing `GithubSyncJob` for `OrgB`'s stack — an action normally gated by `OrgB`'s real webhook secret, achieved without ever knowing it.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
