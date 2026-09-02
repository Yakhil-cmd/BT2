### Title
Cross-tenant webhook confusion: signature is verified against `repository.owner.login`, but the acted-upon repository is resolved from the unauthenticated `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against using `repository_owner`, which is read straight from the JSON body (`params.dig('repository','owner','login')`), and every `Shipit::Webhooks::Handlers::Handler` subclass then resolves which `Repository`/`Stack` to mutate using a *different* field from the same unauthenticated body, `payload.dig('repository','full_name')`. In a multi-organization Shipit install (explicitly documented and supported), these two fields are never checked for consistency.

### Finding Description
`WebhooksController#verify_signature` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

This looks up the `webhook_secret` configured for whatever organization name is embedded in the JSON body under `repository.owner.login`, and validates the HMAC signature against that org's secret [3](#0-2) . Shipit explicitly supports configuring multiple, independent GitHub Apps/orgs with separate `webhook_secret`s in the same instance [4](#0-3) .

Once the signature passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` is invoked [5](#0-4) . All default handlers (`PushHandler`, `StatusHandler`, `MembershipHandler`, `CheckSuiteHandler`, and the `PullRequest::*` handlers) resolve the target `Repository`/`Stack` using the *body's* `repository.full_name` field via `Handler#repository_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

`repository.owner.login` (used to pick the *authenticating* secret) and `repository.full_name` (used to pick the *target* stack that gets written to) are two independent, attacker-controlled JSON fields in the same unauthenticated request body — nothing binds them together. This is exactly the class of bug described in the external report: a value that is checked/authenticated (`_signer`/owner) is not the same value that is actually acted upon (the transaction target) — here, the org whose secret authenticates the request is not the repository whose Stack gets mutated.

### Impact Explanation
An attacker who is an administrator of *any one* organization/repository that is legitimately configured as a tenant in a multi-org Shipit deployment (and therefore knows or controls that org's `webhook_secret`, which they set up themselves when installing their own GitHub App) can forge a webhook payload with:
- `repository.owner.login` = their own organization (so `Shipit.github(organization: ...)` picks their own secret and the HMAC they compute with it verifies), and
- `repository.full_name` = a *different* victim organization's repository already tracked by Shipit.

Because `repository_name`, not `repository_owner`, drives the actual data mutation, this forged-but-"validly-signed" webhook is processed against the victim's stack:
- `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` on the victim stack, forcing Shipit to sync/re-evaluate arbitrary shas as if pushed [7](#0-6) .
- `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`, and the `PullRequest::*` handlers (labeling/archiving/unarchiving review stacks, updating PR metadata) can similarly be triggered against the victim's repository/stacks/commits, e.g. forcing a commit status to `success` which can unblock CI-gated deploys, or archiving/unarchiving a review stack.

This crosses a repository/tenant trust boundary using credentials the attacker legitimately controls only for their *own* tenant — i.e., a cross-repository/cross-organization write, which matches the report's "High: cross-repository writes" / unauthorized state-changing action class.

### Likelihood Explanation
Requires: (1) Shipit configured in multi-org/multi-tenant mode (explicitly documented and supported), and (2) attacker has legitimate control of a webhook secret for at least one configured organization (their own installed GitHub App) — not requiring any GitHub or Shipit privileges over the victim organization. This is a realistic setup for shared/hosted Shipit instances serving several orgs. No repository write access, `ApiClient` token, or Shipit session is required — only the ability to send an HTTP POST with a self-computed HMAC signature.

### Recommendation
Bind authentication to the entity that is actually acted upon: verify the webhook signature using the secret associated with `repository.full_name` (or verify that `repository.owner.login` matches the owner portion of `repository.full_name`) before dispatching to handlers, rather than trusting an independently-controlled `repository.owner.login`/`organization.login` field to select the verifying secret.

### Proof of Concept
1. Shipit is configured with two tenants, `attacker-org` and `victim-org`, each with their own GitHub App and `webhook_secret` (per `config/secrets.development.shopify.yml` multi-org format) [4](#0-3) .
2. Attacker knows `attacker-org`'s `webhook_secret` (they configured it).
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha already known to exist in victim stack's git history>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org_webhook_secret, body)` and sets `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against the attacker's own known secret [8](#0-7) .
6. `PushHandler#process` resolves `stacks` from `repository.full_name` = `"victim-org/victim-repo"` and calls `sync_github` on the victim's stack [7](#0-6) [9](#0-8) , even though the signature was never verified with `victim-org`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
