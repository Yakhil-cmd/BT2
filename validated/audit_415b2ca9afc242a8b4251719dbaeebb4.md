### Title
Cross-Organization Commit Status Forgery via Unscoped `StatusHandler` Lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The external report's root cause is a value that is *acted upon* by privileged math but never bound-checked against the trust context it was verified under (`totalGrantAmount` used unchecked against the Merkle-root-approved bounds). The direct analog in shipit-engine is `StatusHandler#process`, which writes a GitHub commit-status record keyed purely by `sha`, with no verification that the `sha` belongs to the organization/repository whose secret was used to authenticate the inbound webhook.

### Finding Description
`WebhooksController#verify_signature` selects which organization's webhook secret to use for HMAC verification based on `repository_owner`, derived from the payload itself: [1](#0-0) [2](#0-1) 

Once the signature is verified for *that* organization, `Shipit::Webhooks.for_event(event)` dispatches the full JSON body to the corresponding handler with no further scoping. For `status` events, `StatusHandler#process` looks up commits **globally by `sha` only**, with no constraint tying the match back to the organization/repository that was authenticated: [3](#0-2) 

Contrast this with `PushHandler` and `CheckSuiteHandler`, which at least scope through `Repository.from_github_repo_name(repository_name)`: [4](#0-3) 

The binding that should hold is:
`organization authenticated via webhook_secret (repository_owner)` == `organization/repository whose Commit row is mutated`

`StatusHandler` breaks this equality entirely — it never reads `repository_owner`/`repository.full_name` at all, so **any** organization onboarded into this Shipit instance, using **its own legitimately-configured webhook secret**, can submit a `status` event whose `sha` field matches a commit belonging to a completely different organization's stack. Because `Commit.where(sha: params.sha)` is not scoped to a repository, the forged status is written directly to that unrelated commit's status history.

### Impact Explanation
Commit statuses drive deploy gating logic (`CommitChecks`, `Status::Group`, `Stack` deployable checks) — Shipit stacks commonly require specific statuses (e.g., CI/build) to be green before allowing a deploy through the merge queue or task creation UI. An attacker who administers any single organization connected to this multi-tenant Shipit install (a completely unprivileged position relative to the victim org — they only know their own org's `webhook_secret`, which they legitimately possess since they configured their own GitHub App) can:
1. Craft an arbitrary `status` webhook JSON body (any `sha`, `state: success`, `context`, `description`).
2. Sign it with their own org's `webhook_secret` (HMAC-SHA1) — this passes `verify_webhook_signature` because verification only checks organization A's secret against organization A's own payload bytes, not that the payload's semantic target belongs to organization A.
3. Have that forged "success" status written against a commit `sha` belonging to a victim organization's stack, since `Commit.where(sha: params.sha)` performs no organizational scoping.

This can mark an unreviewed/malicious commit as passing required checks in a victim's stack, enabling an unauthorized deploy of that commit through Shipit's normal deploy flow — matching the "unauthorized deploy" impact category.

### Likelihood Explanation
Requires only that: (a) the Shipit instance supports multiple organizations/repos (the standard multi-tenant configuration illustrated in `docs/setup.md` and `template.rb`, each with independently configured `webhook_secret`), and (b) the attacker legitimately controls at least one such organization (a low bar — e.g. any customer/org given self-service onboarding). No compromise of the victim org, no `ApiClient` token, no repository write access on the victim repo, and no session are needed. The only non-trivial requirement is knowing/guessing a real commit `sha` in the victim stack, which is often publicly visible (public repos, PR pages, CI logs) — well within an unprivileged attacker's reach, unlike a true cryptographic collision.

### Recommendation
Scope `StatusHandler` (and any other handler that doesn't already do so) to the organization/repository verified during signature checking. Pass `repository_owner` (or the full verified repository identity) from `WebhooksController` into the handler, and in `StatusHandler#process` restrict the `Commit` lookup to `stacks` (as `PushHandler`/`CheckSuiteHandler` already do via `Repository.from_github_repo_name(repository_name)`), rejecting/ignoring status updates for commits outside the authenticated repository's stacks.

### Proof of Concept
1. Attacker legitimately owns GitHub org `attacker-org`, onboarded into the shared Shipit instance with its own `webhook_secret` `S_A` (set by the attacker themselves when installing their GitHub App, per `docs/setup.md`).
2. Attacker learns (via a public repo, PR, or CI dashboard) the commit sha `deadbeef...` of a commit in victim stack `victim-org/victim-repo`.
3. Attacker crafts a JSON body:
```json
{ "sha": "deadbeef...", "state": "success", "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" } } }
```
4. Attacker computes `sha1=` HMAC over the raw body using `S_A` and sends:
```
POST /github/webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<hmac>
```
5. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org`, fetches `Shipit.github(organization: 'attacker-org')`, verifies successfully against `S_A`. [1](#0-0) 
6. `StatusHandler.call(params)` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, writing a forged "success" status onto the victim's commit despite the request having been authenticated only for `attacker-org`. [3](#0-2)

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
