### Title
Webhook signature bypass via secret-less GitHub organization enables cross-repository CI status forgery and unauthorized deploys - (File: `lib/shipit/github_app.rb`, `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification from an **unverified** field of the incoming payload, and `GitHubApp#verify_webhook_signature` unconditionally treats the request as authentic whenever that organization has no `webhook_secret` configured. Combined with `StatusHandler#process`, which resolves the target `Commit` purely by `sha` with no binding back to the repository/organization that was "verified," an attacker who knows of any onboarded GitHub organization without a configured `webhook_secret` can forge a `status` webhook that fabricates a passing CI status for a commit belonging to an entirely different, secured organization/repository — defeating `ci.require` gating and enabling an unauthorized deploy.

### Finding Description
The signature check picks the signing secret using a payload field read before verification: [1](#0-0) [2](#0-1) 

`repository_owner` is taken straight from the JSON body (`params.dig('repository', 'owner', 'login')`) — nothing has been authenticated yet at this point. That value is used to pick which `GitHubApp` instance (and thus which `webhook_secret`) performs verification: [3](#0-2) 

Critically, `verify_webhook_signature` returns `true` unconditionally when the selected organization has no `webhook_secret` configured (`return true unless webhook_secret`). This is a documented, supported configuration state (`webhook_secret` is optional per `docs/setup.md`), so a Shipit instance hosting multiple GitHub organizations can legitimately have one org with a secret and another without one.

Once the request passes `verify_signature`, `WebhooksController#create` dispatches the entire (attacker-controlled) payload to handlers keyed only by `X-Github-Event`, with no re-validation that the organization used for signing matches the repository the handler will act on: [4](#0-3) 

For the `status` event, `StatusHandler#process` looks up commits **globally by `sha` alone**, with no scoping to any repository or organization at all: [5](#0-4) 

This breaks the trust binding: `organization_verified_via(repository.owner.login)` == `organization_that_owns(target_commit_being_written)`. The payload field that determines *whose secret is checked* (`repository.owner.login`, from an org with no secret) is decoupled from the field/behavior that determines *what gets written* (`sha`, matched across all commits/repos/orgs tracked by the Shipit instance).

### Impact Explanation
An attacker with no Shipit session, API token, or GitHub credentials can:
1. Send a POST to the public webhooks endpoint with `X-Github-Event: status`, a body where `repository.owner.login` is set to any onboarded organization lacking a `webhook_secret`.
2. Set `sha` to the SHA of a commit belonging to a *different*, secured organization's tracked stack, `state: "success"`, and `context` matching a value listed in that stack's `ci.require` in `shipit.yml`.
3. `verify_signature` passes trivially (secret-less org), and `StatusHandler` creates a fabricated passing `Status` on the targeted commit via `commit.create_status_from_github!`.
4. This satisfies the stack's CI-required-status gate, allowing an unauthorized deploy of that commit through Shipit's normal deploy flow.

This matches the Critical impact category "an unauthorized deploy" — the forged CI status is written cross-organization/cross-repository purely from an unauthenticated HTTP POST.

### Likelihood Explanation
Requires only knowledge (or guessing) of an organization slug hosted on the same Shipit instance that has no `webhook_secret` set — a state explicitly permitted by the application's own setup documentation — plus the target commit SHA and required CI context name, both of which are typically discoverable (public commit SHAs, `shipit.yml`'s `ci.require` is not secret). No privileged credentials of any kind are needed.

### Recommendation
- Verify webhook signatures against the secret of the organization that actually owns `repository.full_name`, not a value the payload alone selects, and reject the request if that organization has no secret configured (never silently pass verification).
- Scope `StatusHandler` (and any handler resolving records purely by attacker-supplied identifiers like `sha`) to the repository resolved from the verified payload, consistent with `Handler#stacks`/`Handler#repository_name`.
- Consider making `webhook_secret` mandatory for any organization enabled in a multi-tenant Shipit deployment.

### Proof of Concept
1. Configure Shipit with two organizations: `secured-org` (has `webhook_secret`) and `open-org` (no `webhook_secret`), both with tracked stacks.
2. As an unauthenticated attacker, POST to `/shipit/github/webhooks` (or engine-mounted path):
```
X-Github-Event: status
Body:
{
  "repository": {"owner": {"login": "open-org"}, "full_name": "open-org/whatever"},
  "sha": "<sha of commit belonging to secured-org's stack>",
  "state": "success",
  "context": "<ci context required by secured-org's shipit.yml ci.require>",
  "target_url": "https://example.com",
  "created_at": "2026-09-02T00:00:00Z"
}
```
3. `verify_signature` resolves `Shipit.github(organization: 'open-org')`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (absent/incorrect) `X-Hub-Signature` header.
4. `StatusHandler` matches the commit purely by `sha` (no org/repo check) and creates a fake passing status, satisfying `secured-org`'s CI gate for deploy.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
