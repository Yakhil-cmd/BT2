### Title
Webhook organization-authentication is not bound to the repository/commit acted upon, allowing cross-tenant CI-status forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` resolves the GitHub App/secret used to authenticate an inbound webhook purely from a payload field (`repository.owner.login` / `organization.login`), then hands the *entire, attacker-controlled* payload to the matching event handler. `StatusHandler`, one of the built-in handlers, never re-checks that the `sha` it receives belongs to a commit owned by the organization that produced a valid signature — it looks the commit up globally by SHA across the whole Shipit instance. This breaks the binding "organization that authenticated == repository/commit that is written."

### Finding Description
`Shipit::WebhooksController#verify_signature` picks the GitHub App configuration (and therefore the HMAC secret used to validate `X-Hub-Signature`) using `repository_owner`, itself read straight out of the untrusted JSON body: [1](#0-0) [2](#0-1) 

The signature is verified with `GitHubApp#verify_webhook_signature`, an HMAC over the raw body using that organization's own configured `webhook_secret`: [3](#0-2) 

Once verified, `WebhooksController#create` dispatches the *whole* raw payload — including any `sha`, `repository`, `state`, etc. an attacker chooses — to the registered handler for the event type: [4](#0-3) 

Most handlers scope their side effects to the repository named in the payload via `Handler#repository_name`/`#stacks`: [5](#0-4) 

However, `StatusHandler`, which writes GitHub commit-status data used for CI gating, does not use `repository_name`/`stacks` at all. It resolves the target `Commit` purely by SHA, globally across the entire Shipit instance, and then writes the attacker-supplied status onto it: [6](#0-5) 

So the equality that should hold — `organization authenticated by the signature == organization/repository that owns the commit being written` — is never enforced. Any tenant organization onboarded onto a (potentially multi-org) Shipit installation, who legitimately knows only *their own* `webhook_secret` (configured per-organization exactly as documented for multi-org setups), can produce a validly-signed webhook body whose `repository.owner.login`/`organization.login` matches their own org (so `verify_signature` passes using their own real secret), while the `sha`/`state`/`context` fields inside that same signed body target a commit belonging to a completely different tenant's stack.

### Impact Explanation
`commit.create_status_from_github!` populates the commit statuses that Shipit's `ci.require`/`ci.blocking` checks and continuous-deployment/merge-queue logic rely on to decide whether a commit is safe to deploy or merge. Forging a `success` status on a commit the attacker does not own — bypassing the real GitHub CI checks entirely — can let a stack proceed with an unauthorized deploy or merge for another organization's repository. This matches the "Critical" bucket: unauthorized deploy/merge caused by an authentication binding that is checked against the wrong entity.

### Likelihood Explanation
Exploitation only requires: (1) the attacker controls a legitimately onboarded organization on a shared/multi-org Shipit instance (a normal, documented deployment topology — see multi-org config in `docs/setup.md`), and (2) knowledge of a target commit SHA belonging to another tenant (visible from the Shipit stack pages/API, GitHub itself, or brute-forced from a public repo's commit history). No access to the victim's `webhook_secret`, GitHub token, or Shipit session is needed. This is a realistic though not trivial likelihood — hence moderate.

### Recommendation
In `StatusHandler` (and any other handler that does not already scope by `repository_name`), verify that the commit(s) matched by `sha` actually belong to a repository owned by the same organization (`repository_owner`) that produced the verified signature, before writing any status. More generally, `WebhooksController#verify_signature` should pass the resolved/authenticated organization down to handlers, and every handler should assert that the repository/organization referenced in the payload it acts upon matches the one that was cryptographically authenticated, rather than trusting untrusted payload fields for both authentication and action scope independently.

### Proof of Concept
1. Tenant org `acme` is legitimately onboarded to a shared Shipit instance and knows its own `webhook_secret` (`acme_secret`).
2. Attacker (as `acme`'s GitHub App or anyone who can compute HMAC-SHA1 with `acme_secret`) builds a body:
```json
{
  "repository": { "owner": { "login": "acme" } },
  "sha": "<victim-org's commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Computes `X-Hub-Signature: sha1=<hmac_sha1(acme_secret, body)>` and sends `POST /webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: 'acme')` → resolves acme's real app/secret → `verify_webhook_signature` succeeds (legitimately signed). [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim org's commit regardless of the authenticated org — and writes a forged `success` status onto it. [6](#0-5) 
6. The victim stack's CI-gated deploy/merge-queue checks now see a fabricated green status for that commit.

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
