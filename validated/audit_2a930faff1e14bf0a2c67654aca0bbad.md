### Title
Webhook signature verification binds the wrong field to the HMAC secret, enabling cross-organization event forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate a GitHub webhook against using a field taken from the **same unverified JSON body** it is about to validate, rather than from any independently authenticated source (e.g. a GitHub App installation ID bound at delivery time). Any downstream handler that trusts other fields of that same payload (such as `repository.full_name`) to decide which `Stack`/`Repository` to act on inherits an unverified binding between "the organization whose secret authenticated this request" and "the repository the request claims to be about."

### Finding Description
`verify_signature` picks the HMAC secret like this: [1](#0-0) [2](#0-1) 

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
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

The signature itself is validated with plain HMAC-SHA1 over the raw body using the secret belonging to whichever organization `repository_owner` names: [4](#0-3) 

Because the entire request (including the JSON body) is attacker-supplied to this endpoint (it only needs to be a syntactically valid HTTP POST, not an actual GitHub-signed delivery), an attacker who possesses **any one organization's `webhook_secret`** configured in this Shipit instance (e.g., because they administer that org's own GitHub App/webhook integration in a multi-tenant Shipit deployment) can:
1. Set `repository.owner.login` (or `organization.login`) to the org whose secret they know, so `verify_signature` fetches and validates against the secret they possess.
2. Independently set other fields consumed by the event handlers — most importantly `repository.full_name` / `repository.name`, which the `push`, `status`, `check_suite`, and `pull_request` handlers use to resolve the target `Stack`/`Repository` — to point at a **completely different** organization/repository hosted on the same Shipit instance.

Because the signature check only proves "this body was HMAC'd with Org A's secret," it says nothing about whether the repository identifiers embedded elsewhere in that same body actually belong to Org A. The verified value (organization identity via secret) and the acted-upon value (target repository identity used for stack lookup) are two different payload-derived fields that are never cross-checked against each other, breaking the binding: `organization that authenticated == repository that is written`.

### Impact Explanation
An attacker controlling one organization's webhook secret in a multi-org Shipit deployment can forge webhook events (push, commit status, check_suite completion, pull_request opened/labeled/closed) that other handlers apply to a `Stack` belonging to a repository/org they do not own. Depending on which handler is targeted this can:
- Inject forged commit `Status` records that satisfy `ci.require` checks, unblocking or accelerating an unauthorized deploy on someone else's stack.
- Trigger `GithubSyncJob` to record fabricated commits/refs against another repository's stack.
- Create/close/label review-stack pull requests for another team's repository via the `pull_request/*` handlers.

This crosses the "cross-repository writes" / "unauthorized deploy" bar for Critical impact defined in scope.

### Likelihood Explanation
Exploitation requires the attacker to already possess a valid `webhook_secret` for *some* organization configured in the target Shipit instance — a realistic scenario for any multi-tenant/shared Shipit deployment where multiple GitHub orgs each configure their own app/secret (as documented for `Shipit.github`/`GitHubApp` multi-org config). No Shipit session, `ApiClient` token, or GitHub repository write access to the *victim* repository is required, satisfying the "unprivileged attacker" constraint relative to the targeted stack.

### Recommendation
Do not let any payload-derived field select the verification secret and simultaneously be used un-checked for authorization/routing decisions. Options:
1. Verify the signature using a secret bound to the *specific GitHub App installation* that delivered the webhook (e.g., via the `X-GitHub-Hook-Installation-Target-ID` header or an installation ID resolved out-of-band), not a value read from the JSON body.
2. After signature verification, re-derive the organization from the verified installation identity and assert it matches `repository.owner.login` used by handlers before dispatching to `Shipit::Webhooks.for_event(event)`.

### Proof of Concept
1. Shipit is configured with two organizations, `victim-org` and `attacker-org`, each with their own GitHub App and `webhook_secret` (per `lib/shipit/github_app.rb` multi-org config).
2. Attacker (who legitimately administers `attacker-org`'s GitHub App and therefore knows its `webhook_secret`) crafts a JSON body:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "sha": "<attacker chosen>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(attacker-org secret, body)>` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully because the attacker used the correct secret for that org.
5. The `status` handler processes the payload using `repository.full_name` = `victim-org/victim-repo`, writing a forged commit status onto the victim stack — despite the signature never having proven anything about `victim-org`.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
