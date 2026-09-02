### Title
Webhook signature verification keyed on an unauthenticated payload field allows cross-repository event forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to validate the incoming request against by reading `repository_owner` directly out of the **unauthenticated, attacker-controlled** JSON body, before any HMAC check has occurred. The event handlers that subsequently act on the request use other, independent fields from that same unverified body (notably `repository.full_name`) to determine which tracked `Stack`/`Repository` to mutate. Because the field used to pick the verification secret is never tied to the field used to select the repository that is written, an attacker can choose an organization whose config has no `webhook_secret` configured to trivially defeat signature verification, while pointing the rest of the payload at a completely different, victim repository.

### Finding Description
`verify_signature` computes: [1](#0-0) [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`repository_owner` is read from `params`, which is parsed straight from `request.raw_post` — i.e. attacker-supplied JSON with no authentication at this point. This value is used solely to pick which `GitHubApp` configuration's secret is used for the HMAC check.

`GitHubApp#verify_webhook_signature` short-circuits when no secret is configured for that organization:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

So, for a multi-organization Shipit deployment (documented as a supported configuration in `config/secrets.development.example.yml`) where at least one configured organization key has no `webhook_secret` set, an attacker can:
1. Set `repository.owner.login` (or `organization.login`) in the forged payload to that unprotected organization's name, so `Shipit.github(organization: repository_owner)` resolves to a `GitHubApp` with `webhook_secret` blank, and `verify_webhook_signature` returns `true` unconditionally — no valid `X-Hub-Signature` is required.
2. Independently set `repository.full_name` (and other repository identifiers used by the actual event handler, e.g. `Shipit::Webhooks::Handlers::*`, `GithubSyncJob`) to point at a **different**, real, tracked repository/stack that the attacker does not control and has no legitimate credentials for.

Because `create` dispatches purely on `event` and passes the whole (forged) `params` to the handler chain without re-checking that `repository.full_name`'s owner matches the `repository_owner` used for signature selection, the handler acts on the victim repository using entirely unauthenticated attacker data.

```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [4](#0-3) 

This is the same class of bug as the Sablier report: a field that is *acted upon* downstream (`repository.full_name`, driving `GithubSyncJob`, commit `Status` creation, `Membership`/`User` creation, etc.) is never *covered* by the field that gates authentication (`repository.owner.login` used purely to pick a secret). The equality that should hold — "the organization whose secret authenticated the request == the repository namespace being written to" — is broken.

### Impact Explanation
An unauthenticated network attacker who can reach the `/webhooks` endpoint can forge `push`, `status`, `check_suite`, or `membership` events for any repository/stack tracked by Shipit, as long as any configured GitHub organization in the deployment lacks a `webhook_secret`. Concretely this allows: queuing `GithubSyncJob` for an arbitrary stack (forcing sync to an attacker-chosen SHA), injecting fake commit `Status` records that influence merge-queue/deploy gating logic, and fabricating `membership`/`team` records that create `User`/`Team` rows. Depending on how those downstream effects are consumed (e.g., statuses gating automated deploys, merge-queue decisions), this can escalate into unauthorized deploy/merge decisions — matching the "unauthorized deploy" / "cross-repository writes" impact bar.

### Likelihood Explanation
Requires a specific but plausible deployment configuration: multiple GitHub organizations configured under `Shipit.github`, where at least one has no `webhook_secret` set (the setup docs mark `webhook_secret` as *optional*, and the example secrets files even ship with `webhook_secret: null`). No credentials, session, or GitHub App key are required by the attacker — only knowledge (or a guess) of an organization name lacking a secret and the target repository's `full_name`. This is a realistic misconfiguration for multi-tenant Shipit installs incrementally onboarding organizations.

### Recommendation
- Do not select the verification secret using an unauthenticated payload field. Verify the signature first against every configured secret (or against a single, deployment-wide secret) before dispatching to handlers.
- Reject requests when no `webhook_secret` is configured, or require signature verification for every organization consistently rather than defaulting to `true`.
- After verification, enforce that the organization used to select/verify the secret matches the owner embedded in `repository.full_name` (and any other repository-identifying fields consumed by handlers) before processing the event.

### Proof of Concept
1. Deploy Shipit with two GitHub orgs configured: `org-a` (has `webhook_secret: "s3cr3t"`, tracks no repos of interest) and `org-b` (`webhook_secret: nil`, legitimately used for other things but with no secret set).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and no (or garbage) `X-Hub-Signature`, and body:
```json
{
  "organization": { "login": "org-b" },
  "repository": { "owner": { "login": "org-b" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
3. `repository_owner` resolves to `"org-b"`; `Shipit.github(organization: "org-b").verify_webhook_signature` returns `true` because `webhook_secret` is blank for `org-b` — regardless of the (missing/invalid) `X-Hub-Signature`.
4. `Shipit::Webhooks.for_event('push')` handlers run against `repository.full_name = "victim-org/victim-repo"`, enqueuing `GithubSyncJob` for that stack with the attacker-chosen SHA, even though the attacker never authenticated anything related to `victim-org`.

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
