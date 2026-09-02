### Title
Webhook signature scope confusion allows cross-organization commit status forgery leading to unauthorized deploys - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / webhook secret used to authenticate an inbound webhook based on `repository.owner.login` (or `organization.login`) taken from the **unverified** JSON body, but the payload processing performed afterwards (in particular `StatusHandler`) is not scoped to that same organization/repository. This breaks the trust binding "organization whose secret authenticated the request" == "repository/commit the request is allowed to act on," analogous to the reported Algebra bug where the entity that authorized an operation (`enterFarming`) diverged from the entity actually mutated (pool liquidity vs. farming liquidity).

### Finding Description
`verify_signature` picks the GitHub App config purely from attacker-controlled JSON fields: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

Shipit explicitly supports hosting multiple, independently trusted GitHub organizations behind one instance, each with its own `webhook_secret` [3](#0-2) . `verify_webhook_signature` additionally treats a missing/blank `webhook_secret` as automatic success: [4](#0-3) 
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
```
so any organization configured without a webhook secret (an explicitly documented, valid configuration — see `webhook_secret: some-secret-value` being called "optional" in `docs/setup.md`) grants signature-free acceptance of any payload whose `repository.owner.login` matches that org's name.

Once the request passes `verify_signature`, the event body is dispatched to handlers keyed only by `X-Github-Event`, with no re-validation that the payload's actual target (commit SHA / repository) belongs to the organization that was used to authenticate it: [5](#0-4) 

Critically, `StatusHandler` — which creates commit-status records that gate deployability — resolves its target purely by SHA, globally, with **no repository/organization scoping at all**: [6](#0-5) 
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
Compare this to other handlers, which correctly scope lookups through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before acting [7](#0-6) . `StatusHandler` has no such check, so the binding "organization that authenticated the webhook" is never even compared against "repository/commit whose status is written."

The equality that should hold but is not enforced:
`organization(secret used to authenticate) == owner(repository whose commit status/state is mutated)`

### Impact Explanation
An attacker who controls (or is granted webhook access to) any single organization configured on a shared multi-tenant Shipit instance — or who targets an organization configured with no `webhook_secret` — can forge a valid, signed (or unsigned-but-accepted) `status` event whose `sha` matches a commit belonging to an entirely different organization's stack. `commit.create_status_from_github!` writes a fabricated CI status (e.g., `state: "success"`, matching a `ci.require` context as documented for gating deploys/continuous delivery, README `ci.require` section: [8](#0-7) ). This can satisfy required-status checks used to unlock deployability/continuous deployment for a stack the attacker has no legitimate access to, resulting in an **unauthorized deploy** — the impact category explicitly listed as Critical.

### Likelihood Explanation
Exploitation requires the attacker to know (a) a valid `X-Hub-Signature` secret for *some* organization hosted on the instance (trivial if that org has no `webhook_secret` configured, which is an explicitly supported/optional setup) and (b) the target commit SHA of the victim stack (obtainable by observing the public commit history of the target's open-source repo, Shipit UI, or the target's own GitHub notifications). No Shipit session, `ApiClient` token, or GitHub App private key is required — only the ability to POST to the public `/webhooks` endpoint, matching the "no privileged Shipit credentials" bar in scope. This is realistic specifically in multi-org Shipit deployments (an intended, documented configuration).

### Recommendation
- In `WebhooksController#verify_signature`/`repository_owner`, after signature verification succeeds, verify that the concrete `repository.full_name` (or `organization.login`) referenced by the payload actually belongs to the same organization whose secret validated the signature, and reject otherwise.
- Fix `StatusHandler#process` (and any other handler that doesn't scope through `Handler#stacks`/`repository_name`) to scope `Commit` lookups by the repository identified in the payload, not by SHA alone, mirroring the pattern used in the pull-request handlers.

### Proof of Concept
1. Operator configures Shipit with two organizations, `attacker-org` (webhook secret left blank per the documented "optional" setting) and `victim-org` (tracks stack `victim-org/app`, requires CI context `ci/tests` before deploy).
2. Attacker discovers the SHA of a pending commit on `victim-org/app` (public repo or via Shipit's own stack page, which is world-readable in typical unauthenticated setups documented for Shipit).
3. Attacker POSTs to `/webhooks` with `X-Github-Event: status` and body:
```json
{
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/whatever"},
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/tests",
  "created_at": "2026-09-02T00:00:00Z"
}
```
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")`; since that org has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally, so the request is accepted with no valid signature at all.
5. `StatusHandler#process` runs `Commit.where(sha: "<victim commit sha>")`, finds the victim's commit (it exists globally in the shared DB regardless of `attacker-org`), and creates a forged `success` status for `ci/tests`, potentially unlocking deploy/continuous-delivery gating for `victim-org/app` despite the attacker having no access to `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** README.md (L444-450)
```markdown
<h3 id="ci">CI</h3>

**<code>ci.require</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to disallow deploys if any of them is missing on the commit being deployed.

For example:
```yml
ci:
```
