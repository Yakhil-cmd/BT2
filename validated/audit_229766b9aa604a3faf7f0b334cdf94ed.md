### Title
Cross-organization commit status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely by `sha` across the entire database and calls `create_status_from_github!` on every match, without ever checking that the webhook's authenticated organization (`repository_owner`) owns the stack/repository that the matched `Commit` belongs to. `Handler#stacks`/`#repository_name` exist for scoping but are never consulted by `StatusHandler`, so a validly-signed webhook from any attacker-owned GitHub organization can write a status onto any commit sha it knows about, even one belonging to a completely unrelated victim repository.

### Finding Description
The binding that must hold is: `organization verifying the payload (repository_owner from WebhooksController#verify_signature) == organization owning the Commit row being mutated`. This is never checked for the `status` event.

Trace:
- `WebhooksController#create` parses the JSON body and dispatches to handlers for the event without any repository/org scoping: [1](#0-0) 
- `verify_signature` only confirms the payload is validly signed *for the organization named in the payload itself* (`repository_owner`, which falls back to `organization.login` when there is no `repository` key): [2](#0-1) [3](#0-2) 
  This proves the attacker legitimately controls the *attacker's own* org's webhook secret — it says nothing about which `Commit`/`Stack` the payload is allowed to mutate.
- `Handler` base class provides `repository_name`/`stacks` helpers meant for scoping mutations to the repository named in the payload: [4](#0-3) 
- `StatusHandler#process` ignores those helpers entirely and instead does a **global** lookup by `sha` alone, then mutates every matching commit regardless of owning org/repository: [5](#0-4) 

Exploit flow: attacker creates their own GitHub org/app (or any org Shipit is configured to trust) and obtains the ability to send a validly-signed webhook for it (this is normal/expected — any org owner can sign their own webhooks). They learn a victim commit sha (e.g. from a public, unauthenticated stack page or `git log` on the public repo). They POST `/webhooks` with `X-Github-Event: status`, a body containing only `{"sha": "<victim sha>", "state": "success", "organization": {"login": "attacker-org"}}` and no `repository` key, signed with the attacker org's own webhook secret. `verify_signature` passes because the signature is valid for `attacker-org`. `StatusHandler#process` then finds the victim's `Commit` row (owned by a different stack entirely) purely by sha and calls `commit.create_status_from_github!(params)` on it, writing a forged CI status for the victim commit.

Existing guards do not catch this: `verify_signature` validates *who signed*, not *what is being mutated*; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema only validates payload shape (`sha`, `state`, etc.), not ownership; there is no `require_permission!`/`stacks` scoping applied inside `StatusHandler`.

### Impact Explanation
A payload authenticated for one organization/repository mutates another organization's `Commit`/`Status` data — this is the "payload for one repository mutating another's ... commit" Critical category. Forged `Status` rows influence `Commit#state`/CI status aggregation and can flip `deployable?` for a victim stack, potentially unlocking or blocking deploys that should not be possible from CI status alone. This is repeatable against any commit sha the attacker can learn for any repository hosted on the same Shipit instance, and only requires knowledge of a sha (often public) plus control of any org whose webhook signature verifies — including the attacker's own trivial org if Shipit is configured to accept it, or any org already onboarded to the instance.

### Likelihood Explanation
Preconditions: the victim `Commit` row must already exist in Shipit's DB (created when the stack polled/synced the commit) and the attacker needs a validly-signed webhook for *any* organization known to the Shipit instance — most straightforwardly their own, if `Shipit.github_teams`/org configuration allows self-service org registration, or any org they can act as GitHub app installer for. Cost is a single crafted HTTP POST; no privileged Shipit role, session, or secret of the victim's is required. Feasibility is high given the sha is often discoverable from public stack pages, GitHub commit history, or CI links.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to repositories owned by the verified webhook organization instead of a global sha lookup — e.g. restrict to `stacks`/`repository_name`-derived repositories (mirroring other handlers), or explicitly compare each matched commit's `Stack#repository`/organization against `repository_owner` before calling `create_status_from_github!`, skipping/rejecting non-matching commits.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, or controller-level in `test/controllers/webhooks_controller_test.rb`):
1. Create a victim `Stack`/`Repository` (e.g. `victim/repo`) and a `Commit` fixture with a known `sha` under that victim stack.
2. Assert baseline: `commit.statuses.count == 0` and record `stack.deployable?` before the attack.
3. Configure/stub `Shipit.github(organization: 'attacker-org')` such that a validly-signed webhook secret exists for `attacker-org` (as any legitimate org onboarded to the instance would have).
4. POST to `/webhooks` with header `X-Github-Event: status`, body `{"sha": "<victim sha>", "state": "success", "organization": {"login": "attacker-org"}}` (no `repository` key), signed with `attacker-org`'s webhook secret via `X-Hub-Signature`.
5. Assert the request returns `200`/`:ok` (signature verified for attacker-org).
6. Assert `commit.reload.statuses.count == 1` and the new `Status#state == 'success'`, proving a status was written to the victim commit despite `repository_owner == 'attacker-org' != victim's owning organization`.
7. Assert `stack.reload.deployable?` changed accordingly, demonstrating real impact on deploy gating.

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
