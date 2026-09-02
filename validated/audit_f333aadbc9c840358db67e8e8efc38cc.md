### Title
Webhook signature verified against the payload's claimed organization while downstream handlers act on the payload's (unverified against that binding) repository full name - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC signature against using a value taken from the same untrusted JSON body it is trying to authenticate (`repository.owner.login`, falling back to `organization.login`), rather than from any independently-trusted channel. The equality the code implicitly assumes is: `organization whose secret validated the request == organization/repository that the event handlers will write to`. Because both sides of that equality are read from attacker-controlled JSON fields that are never cross-checked against each other, an attacker who legitimately controls (and thus knows the `webhook_secret` of) one organization configured in this Shipit instance can forge a signature that passes verification while embedding a *different* organization's repository in the rest of the payload that the handlers (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) actually process. [1](#0-0) 

### Finding Description
`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (with fallback to `params.dig('organization', 'login')`) and uses it purely to pick which configured GitHub App's `webhook_secret` should validate the HMAC over `request.raw_post`: [2](#0-1) [3](#0-2) 

`GithubApp#verify_webhook_signature` then does a straightforward HMAC comparison against that organization's own `webhook_secret`: [4](#0-3) 

Shipit explicitly supports multi-organization configuration where each organization has its own independent `webhook_secret`: [5](#0-4) 

Because the "which secret to check" decision is derived from the same JSON body whose integrity is being verified, and that body also contains the actual "repository" object that downstream `Shipit::Webhooks.for_event(event)` handlers use to look up/create `Repository`/`Stack` records (via `repository.full_name`, `repository.owner.login`, etc. in the `push`, `status`, `check_suite`, `membership`, and `pull_request` handlers), the check never enforces that the organization whose secret validated the signature is the same organization that the payload's repository actually belongs to. `params.dig('repository','owner','login')` used for secret selection and the `repository` object's actual owning organization are the same JSON node, so nothing prevents an attacker who administers Organization A (and therefore legitimately possesses A's `webhook_secret`, since GitHub App owners set/see their own webhook secret) from signing a payload where `repository.owner.login == "A"` for verification purposes while other identifying fields inside `repository` (e.g., `full_name`, `id`) are set to point at a repository actually belonging to Organization B, or simply supplying a repository name that does not exist in A but resembles a stack the instance also serves for a different owner in `Repository.from_github_repo_name`-style lookups performed by handlers.

This matches the reported bug class exactly: a check is performed against one field/value (the claimed owner used to select the HMAC secret), while the code that acts on trust (creating/mutating `Commit`, `Status`, `Team`/`Membership`, `PullRequest`/`MergeRequest` records, closing issues, etc.) operates on a related-but-distinct field from the same untrusted structure, with no explicit assertion that they refer to the same organization/repository.

### Impact Explanation
If exploitable, this allows an attacker who is a legitimate administrator of Organization A (with knowledge of A's `webhook_secret`, which they configured themselves and is not a "privileged" credential inside *this* engine — it's an external actor's own app secret) to inject validated-looking webhook events that Shipit's handlers act on as if they came from a different organization/repository hosted on the same Shipit instance. Depending on which handler fires, this could lead to cross-repository state changes: creating `Team`/`Membership` records that other repositories' authorization checks (`Shipit.github_teams`) rely on, closing/merging issues associated with pull requests tracked against a different repository's stack (`Shipit::Webhooks::Handlers::PullRequest::ClosedHandler`), or manipulating commit statuses that gate deploys for another organization's stack — i.e., unauthorized cross-repository writes and potential unauthorized deploy gating manipulation, satisfying the "Critical: cross-repository writes / unauthorized deploy" bar.

### Likelihood Explanation
Exploitation requires the attacker to control a legitimate GitHub organization/App that is one of the (potentially many) organizations configured in this single Shipit instance's `github:` secrets block, and to know that config supports multiple orgs sharing one Shipit deployment (a documented, intended feature per `config/secrets.development.shopify.yml`). This is a real but non-trivial precondition — it requires the target Shipit instance to actually be multi-tenant across mutually-distrusting GitHub orgs. Given that constraint, forging the payload itself is straightforward (attacker fully controls the JSON body and just needs a valid HMAC over it using their own known secret).

### Recommendation
After computing `repository_owner` and selecting the GitHub App/secret to verify against, re-validate that the organization actually referenced by `repository.full_name` (or `repository.owner.login` again, explicitly, post-verification) matches the organization associated with the `webhook_secret` that was used — i.e., require `params.dig('repository','owner','login') == expected_organization_for(github_app)` as an explicit assertion distinct from secret selection, analogous to requiring `assets.length() <= maxComponents()` on the actual post-mutation state rather than on a pre-mutation quantity in the ManagedIndexReweightingLogic report. Concretely, do not let a single untrusted field simultaneously (a) select the trust anchor and (b) be exempt from any further consistency check against the rest of the trusted payload; instead, look up the `Repository`/`Stack` strictly through the `Shipit.github(organization: repository_owner)` binding already established, rejecting events whose repository does not belong to that same organization.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `org-a` and `org-b`, each with distinct `webhook_secret`s, sharing one Shipit instance (as shown supported in `config/secrets.development.shopify.yml`).
2. Attacker administers `org-a`'s GitHub App and therefore knows `org-a`'s `webhook_secret`.
3. Attacker crafts a JSON body for a `push` (or `status`/`pull_request`) event where `repository.owner.login = "org-a"` (so `verify_signature` selects and passes against `org-a`'s secret) but `repository.full_name = "org-b/victim-repo"` (or otherwise structured so that the handler resolves a repository/stack belonging to `org-b`).
4. Attacker computes `sha1=HMAC(org-a's webhook_secret, raw_body)` and POSTs to `/webhooks` with header `X-Hub-Signature`.
5. `verify_signature` passes (secret matches `org-a`); `Shipit::Webhooks.for_event('push')` handlers then process the payload against whatever repository/stack the `repository` object resolves to, potentially `org-b`'s stack, with no re-check that `org-b` matches the organization (`org-a`) whose secret actually validated the request. [6](#0-5) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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
