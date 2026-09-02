### Title
Webhook Status/Push handlers act on commits and repositories never covered by the signature's organization scope - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate an incoming webhook's HMAC against based on the *unverified* JSON payload field `repository.owner.login` (or `organization.login`). Once the HMAC check passes for that organization's secret, the individual event handlers act on completely different fields of the same unverified payload — `repository.full_name` (for `PushHandler`, `CheckSuiteHandler`, etc.) or, worse, a bare `sha` with **no repository scoping at all** (`StatusHandler`). This breaks the equality that the signature is supposed to enforce: `organization whose secret signed the payload == repository/commit whose state gets written`.

### Finding Description
`verify_signature` derives the signing organization purely from payload content, not from anything cryptographically bound to a specific repository: [1](#0-0) [2](#0-1) 

The webhook secret used for that HMAC check is a per-organization credential, and Shipit explicitly supports multiple independent organizations/GitHub Apps being registered against a single engine instance, each with its own `webhook_secret`: [3](#0-2) [4](#0-3) 

Once `verified` is true, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs handlers over the same raw, attacker-supplied `params`. The base `Handler` resolves the target repository/stacks from `repository.full_name` — a *different* payload field than the one used to select the signing secret: [5](#0-4) 

Nothing enforces that `repository.full_name`'s owner segment matches `repository.owner.login`/`organization.login` used for signature selection, so a payload signed with organization A's secret can freely claim to be about organization B's repository. `PushHandler` uses this repo/stack resolution to trigger `stack.sync_github`: [6](#0-5) 

`StatusHandler` is worse: it doesn't even use `repository_name`/`stacks` scoping — it looks up commits by bare `sha` across the *entire* database and writes GitHub commit-status state onto them: [7](#0-6) 

So an attacker who legitimately controls one organization onboarded to a shared Shipit instance (and therefore legitimately knows/derives that organization's own `webhook_secret`, which the engine explicitly supports provisioning per tenant) can craft and correctly sign a `status` webhook whose `repository` object claims their own org (satisfying `verify_signature`), while the `sha`/`state`/`context` fields target a commit that actually belongs to a completely different, unrelated repository/stack tracked by the same Shipit instance. `StatusHandler#process` will happily call `commit.create_status_from_github!(params)` on that unrelated commit.

### Impact Explanation
Shipit stacks gate "deployability" of a commit on its aggregated GitHub commit statuses/checks. Forging a `success` status on an arbitrary commit belonging to a repository/stack the attacker does not control can make an otherwise non-deployable (failing/pending CI) commit appear deployable, enabling an unauthorized deploy of that commit by whoever/whatever (human or continuous-delivery automation) next acts on the stack — this maps to the in-scope "unauthorized deploy" Critical impact. It also allows an org-scoped attacker to write into a cross-organization/cross-repository trust boundary they were never granted (`Shipit.github(organization: ...)` is meant to be an isolation boundary between tenants), which maps to the "cross-repository writes" Critical impact bucket as well.

### Likelihood Explanation
This requires the deployment to be configured with more than one organization/GitHub App (the documented multi-tenant configuration in `docs/setup.md`). In that configuration, no additional privilege beyond controlling one of the *already-onboarded* organizations is required — the attacker does not need a Shipit session, an `ApiClient` token, the victim organization's `webhook_secret`, or repository write access on the victim repo. They only need the ability to send a correctly-HMAC-signed HTTP POST to `/webhooks` using their own organization's secret, which is entirely within their control as a legitimate tenant of the shared instance.

### Recommendation
Bind the entire trust decision to a single, consistently-derived scope: after verifying the signature, re-derive/validate that `repository.full_name`'s owner (and any repository/stack subsequently resolved from the payload) is actually owned by the same organization whose secret validated the signature, and reject the webhook otherwise. For `StatusHandler` specifically, additionally scope the `Commit.where(sha: ...)` lookup to commits belonging to stacks/repositories under the verified organization, rather than searching globally.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` (attacker-controlled tenant) and `org-b` (victim tenant), each with a distinct `github.webhook_secret`, per the multi-org setup documented in `docs/setup.md`.
2. Attacker computes `sha1=` HMAC over a crafted JSON body using `org-a`'s known `webhook_secret`:
```json
{
  "sha": "<victim-commit-sha-in-org-b-repo>",
  "state": "success",
  "context": "ci/attacker-forced",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-a/whatever" }
}
```
3. POST this to `/webhooks` with header `X-Github-Event: status` and the computed `X-Hub-Signature`.
4. `WebhooksController#verify_signature` resolves `repository_owner` to `"org-a"`, fetches `org-a`'s `webhook_secret`, and the signature validates.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — unscoped by repository — finds the victim's commit belonging to `org-b`, and calls `create_status_from_github!`, writing a forged `success` status onto a commit the attacker never had access to.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-36)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

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
