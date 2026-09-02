## Title
Cross-organization webhook forgery — the org whose secret verifies `X-Hub-Signature` is never checked against the repository the event writes to - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to HMAC-verify a webhook against using an attacker-supplied field of the *unverified* JSON body (`repository.owner.login` / `organization.login`), then hands the *entire* raw body to every registered `Shipit::Webhooks::Handlers::Handler`. Those handlers independently pick the repository/stack to act on using a *different* field of the same body (`repository.full_name`), and `StatusHandler` doesn't even scope by repository at all. Nothing ties "the org whose secret validated this signature" to "the repository/commit this payload writes to." Any party who legitimately administers one GitHub organization onboarded to a shared Shipit instance (and therefore knows/controls that org's `webhook_secret`) can forge a validly-signed webhook that mutates a stack belonging to a *completely different* organization also hosted by the same Shipit instance.

### Finding Description
`verify_signature` derives the verification key from attacker-controlled JSON before any cryptographic check has occurred: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the per-organization config (including `webhook_secret`) keyed by whatever login string appears in the body: [3](#0-2) 

Once `verify_webhook_signature` succeeds (using *that* org's secret), the controller dispatches the raw, parsed payload to every handler for the event with no further binding: [4](#0-3) 

Handlers resolve the target `Repository`/`Stack` from `repository.full_name`, a field never covered by the signature-selection logic and never cross-checked against `repository.owner.login`: [5](#0-4) [6](#0-5) 

`StatusHandler` is worse: it doesn't consult `repository` at all and matches by commit SHA across the *entire* database, i.e. across every organization/stack hosted by the instance: [7](#0-6) 

**The broken equality:** the code implicitly assumes `org_that_signed(payload) == owner_org(repository_or_commit_acted_on)`. Before an attack, this holds because GitHub only ever sends events for the org that owns the installation whose secret is used. After an attacker's crafted POST, the left side is the attacker's own onboarded org (whose secret they know), while the right side is an arbitrary target chosen via `full_name` (or, for statuses, an arbitrary SHA with no organization check whatsoever).

### Impact Explanation
This breaks the multi-tenant isolation the webhook secret is supposed to provide. An operator of Org A (a legitimate, low-privileged tenant of a shared Shipit install) can:
- Forge `push`/`check_suite`/`pull_request` events that reference Org B's `repository.full_name`, causing `sync_github`, review-stack archival/unarchival, or PR-state mutations on stacks they have no access to.
- Forge `status` events for arbitrary commit SHAs belonging to any stack in the database, fabricating passing/failing CI statuses used by `Stack`/`Commit` deploy-safety gating (`deployable?`, blocking statuses). This can be used to unblock/hide a required check, contributing to an unauthorized deploy on a repository the attacker does not control — this crosses into "cross-repository writes" / "unauthorized deploy" territory (Critical), since the write is performed with Shipit's own trust and GitHub credentials for a repository unrelated to the org whose secret was actually used.

### Likelihood Explanation
The `/webhooks` endpoint is unauthenticated by design (only HMAC-checked) and reachable by anyone. The only prerequisite is administrative control of *any single* organization/App-installation already configured in the shared `Shipit.github` config — a routine, unprivileged-relative-to-other-tenants position in any multi-org Shipit deployment (the shipped `config/secrets.development.shopify.yml` explicitly documents multiple orgs sharing one instance). No repository write access, no `ApiClient` token, no session, and no privileged Shipit account are required.

### Recommendation
After `verify_webhook_signature` succeeds, re-derive the organization strictly from `repository.full_name`'s owner (or `organization.login` for org-level events) and reject the request (422) if it doesn't match the `repository_owner` value that was used to select the verifying secret. Additionally, `StatusHandler` (and any other handler that doesn't already scope by repository) should filter `Commit.where(sha:)` by the repository derived from the verified payload/org rather than matching globally.

### Proof of Concept
1. Shipit instance is configured with two orgs, e.g. `orgA` (attacker-controlled, webhook_secret known to attacker) and `orgB` (victim, has an existing tracked `Stack` and commit `SHA_X`).
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "SHA_X",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgA/whatever" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(orgA_webhook_secret, body)` themselves (they own `orgA`'s secret) and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: 'orgA')`, verifies successfully with `orgA`'s secret.
5. `StatusHandler#process` runs `Commit.where(sha: 'SHA_X')`, which matches the commit in `orgB`'s stack (not `orgA`'s), and calls `create_status_from_github!`, injecting a fabricated `success` status onto a repository/org the attacker never had signing rights over.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
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
