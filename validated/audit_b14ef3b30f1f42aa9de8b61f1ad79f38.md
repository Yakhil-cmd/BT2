### Title
Webhook signature verified against `repository.owner.login`/`organization.login`, but event handlers act on the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and thus the HMAC `webhook_secret`) used to authenticate an inbound webhook based on `repository_owner`, which is read from `repository.owner.login` (or, if absent, `organization.login`) in the raw JSON body. Once the signature is accepted, event handlers act on a *different* field of the same attacker-controlled body — `repository.full_name` — to decide which tracked repository/stack the event applies to. Nothing ties these two fields together, so the organization whose secret authenticated the payload is never checked against the repository the payload actually claims to describe.

### Finding Description
`verify_signature` derives the signing organization purely from body content and fetches the matching per-organization GitHub App/secret: [1](#0-0) [2](#0-1) 

```
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
```

`verify_webhook_signature` only checks the raw body against the secret configured for whatever organization `repository_owner` names — it says nothing about which repository the event is *for*: [3](#0-2) 

The actual event payload is then handed unmodified to handlers, and every handler resolves the target stacks from a *separate* field, `repository.full_name`, with no cross-check against `repository_owner`: [4](#0-3) 

Because Shipit instances commonly track multiple GitHub organizations (each with its own `webhook_secret`/App, as configured in `Shipit.github`), an attacker who legitimately controls the webhook configuration of *any one* onboarded organization (call it `OrgA`) can sign an arbitrary JSON body with `OrgA`'s secret while setting `repository.full_name` (and/or `organization.login`/`repository.owner.login` used only for the initial secret lookup) to point at a completely different, victim organization/repository (`OrgB/some-repo`) that is also tracked by the same Shipit instance. The signature check passes (it only verifies "this came from someone who knows OrgA's secret"), but `Handler#repository_name` then resolves `OrgB/some-repo`'s stacks and dispatches the forged event (`push`, `status`, `check_suite`, etc.) against them.

The equality the code should enforce but does not is:
`organization whose secret authenticated the payload == owner of repository.full_name acted upon by the handler`

### Impact Explanation
This breaks a deployment-trust binding between authentication and the resource actually mutated, matching the "an organization that authenticated versus the repository that is written" analog explicitly called out in scope. Concretely, handlers such as `StatusHandler` and `PushHandler` write commit statuses / commits for the repository named in `repository.full_name`. An attacker controlling one organization's webhook secret can forge a `status` event claiming a **success** CI status for a commit belonging to a victim repository/stack hosted on the same Shipit instance, or forge `push`/`check_suite` events that alter perceived commit/CI state used to gate deploys and merge-queue processing. Since CI status is one of the safety gates Shipit relies on for allowing deploys/merges (`ci.require`, merge queue), forging it for an unrelated repository can lead to an unauthorized deploy/merge — the required Critical/High impact category — without the attacker ever holding a Shipit session, `ApiClient` token, or write access to the victim repository/organization.

### Likelihood Explanation
Requires the attacker to control (or know the webhook secret of) at least one GitHub organization that is legitimately configured on the same multi-tenant Shipit instance — a materially lower bar than compromising the victim organization/repository itself, and explicitly an "unprivileged attacker" relative to the victim tenant. No Shipit credentials, GitHub App private key, or TLS interception is needed; only knowledge of one tenant's `webhook_secret`, which is routinely visible to that tenant's own GitHub org/repo admins (a normal, non-privileged position with respect to *other* tenants on the same Shipit instance).

### Recommendation
After resolving `repository_owner` and verifying the signature, cross-validate that the owner encoded in `repository.full_name` (used by `Handler#repository_name`/`stacks`) matches the organization (`repository_owner`) whose secret validated the signature, rejecting the webhook (422) on mismatch. Alternatively, derive both the signing organization and the acted-upon repository from the same single field (`repository.full_name`) so there is only one source of truth for "which tenant does this payload belong to."

### Proof of Concept
1. Attacker is an admin of `OrgA`, a legitimate organization onboarded to a shared Shipit instance, and knows `OrgA`'s `webhook_secret`.
2. Attacker crafts a `status` (or `push`/`check_suite`) webhook JSON body:
```json
{
  "organization": { "login": "OrgA" },
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, body)` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")` and validates successfully against `OrgA`'s secret.
5. `create` dispatches the event to `StatusHandler`, which resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` and records a forged `success` CI status for `OrgB`'s commit — despite the request never being authenticated for `OrgB`.

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
