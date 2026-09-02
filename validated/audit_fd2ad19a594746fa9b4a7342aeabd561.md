### Title
Cross-organization commit status forgery via `StatusHandler` bypassing repository/organization binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which HMAC `webhook_secret`) to use for verifying an inbound webhook based on the organization named in the payload itself (`repository.owner.login`, falling back to `organization.login`), then dispatches the parsed JSON to the registered handler for the event type. `StatusHandler`, however, never checks that the commit it is about to modify actually belongs to the organization/repository that was used to authenticate the request; it looks up commits globally by SHA across the entire installation.

### Finding Description
`verify_signature` picks the GitHub App used to validate `X-Hub-Signature` purely from a payload-supplied field: [1](#0-0) [2](#0-1) 

Once the signature is accepted, the raw JSON is handed unmodified to the handler: [3](#0-2) 

`StatusHandler#process` then resolves the target purely by commit SHA, with no scoping to the repository/organization that produced the verified signature: [4](#0-3) 

This breaks the intended binding: *the organization whose secret authenticated the request* must equal *the repository/stack whose state is written*. Shipit explicitly supports multiple, separately trusted GitHub Apps/organizations sharing one instance (`docs/setup.md`, "Using Multiple Github Applications"), each with its own `webhook_secret` known to that organization's own administrators. Any one of these organizations can therefore craft an arbitrary `status` event payload, set `repository.owner.login` (or `organization.login`) to their own org so the request is HMAC-verified with a secret they legitimately possess, but populate `sha`, `state`, `context`, etc. to target a commit belonging to a **completely different organization's stack** hosted on the same Shipit instance. `Commit.where(sha: params.sha)` has no repository/stack filter, so the forged status is attached to that foreign commit via `commit.create_status_from_github!`.

This mirrors the reported bug class exactly: the code correctly authenticates one entity (the organization owning the HMAC secret) but then acts on a different, unauthenticated entity (an arbitrary commit/repository) without re-validating the equality between the two, analogous to `getSpentStakingTx` returning/acting on the wrong entity because the loop and the payload structure weren't cross-checked.

### Impact Explanation
Commit statuses directly influence Shipit's safety gates: `required_statuses`, `blocking_statuses`, and `deployable?` are computed from `Status`/`Status::Group` records attached to a commit, and are used by `Stack#trigger_deploy`, the merge queue, and continuous deployment scheduling. By forging a `success` status (or `error`/`failure` for a denial-of-CI attack) on a commit of a tenant they don't control, an attacker with only their own organization's webhook secret can:
- Make an otherwise-blocked commit appear CI-green, satisfying `required_statuses`/blocking checks and enabling an **unauthorized deploy** of that commit for a foreign stack, or
- Corrupt CI state for another tenant (write access to data outside their authorization boundary).

This qualifies as "High" impact per the rubric (escalation of authorization boundary / unauthenticated write of stack state) and can reach "Critical" (unauthorized deploy) depending on how `deployable?`/merge gating is configured for the victim stack.

### Likelihood Explanation
Likelihood is high in any Shipit deployment that follows the documented multi-organization setup (`docs/setup.md`), which is an explicitly supported and encouraged configuration for hosting multiple GitHub orgs' stacks on one instance. Any organization admin who legitimately owns a configured GitHub App (and thus knows their own `webhook_secret`) can perform this attack without any additional privilege — they only need to know (or guess) another tenant's commit SHA, which is often public information (commits are visible on GitHub) or can be observed via Shipit's own UI/API if stacks are visible cross-tenant.

### Recommendation
`Handler` (and specifically `StatusHandler`) must scope lookups by the repository identified during signature verification, not solely by payload-controlled identifiers like commit SHA. Concretely:
- Have `StatusHandler#process` restrict `Commit.where(sha: params.sha)` to commits whose `stack.repository` matches `payload.dig('repository', 'full_name')`/owner, consistent with how `Handler#stacks`/`repository_name` already scope `PushHandler`.
- More generally, `verify_signature` should establish the authenticated organization and pass it (or the resolved `Repository`) into the handler dispatch so every handler can assert that any payload-declared repository/commit actually belongs to that authenticated organization before mutating state.

### Proof of Concept
1. Organization "org-attacker" has a GitHub App installed and configured in Shipit's `secrets.yml` with its own `webhook_secret_attacker` (a fully legitimate, documented multi-org setup per `docs/setup.md`).
2. Attacker (an admin of org-attacker) crafts a `status` webhook JSON body:
```json
{
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-attacker/irrelevant" },
  "sha": "<sha of a commit belonging to victim-org/victim-repo>",
  "state": "success",
  "context": "ci/required-check",
  "created_at": "2026-09-02T00:00:00Z"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_attacker, body)>` — a value they can legitimately compute since they own that secret.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"org-attacker"`, loads that org's `GitHubApp`, and the signature verifies successfully.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, finds the victim's commit (no organization/stack check), and calls `create_status_from_github!`, writing a forged "success" status onto `victim-org/victim-repo`'s commit — potentially unblocking a deploy that Shipit's safety checks would otherwise prevent.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
