### Title
Cross-tenant commit status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits globally by `sha` with no scoping to the repository that authenticated the webhook, while `WebhooksController#verify_signature` only checks the HMAC signature against the secret configured for `repository.owner.login` in the payload. An attacker who owns an org configured in Shipit (org A) can forge a `status` webhook naming a commit sha belonging to a completely different org's stack (org B) and have `create_status_from_github!` mutate org B's commit.

### Finding Description
The claimed binding is: `organization whose webhook_secret verified request bytes == organization owning the mutated commit/stack`. Tracing the code shows this equality is never enforced.

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30,59-62`) resolves `repository_owner` purely from `params.dig('repository','owner','login')` (attacker-controlled JSON) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. This only proves the request bytes were signed with org A's `webhook_secret`; it says nothing about which commit/stack the payload's `sha` refers to.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This is a global, unscoped lookup by `sha` across all stacks/tenants. It never calls `Handler#repository_name`/`Handler#stacks` (defined in `app/models/shipit/webhooks/handlers/handler.rb:32-38`) to restrict matching commits to the repository that authenticated the request. Other handlers (e.g., push/pull-request handlers) typically use `stacks` to scope work, but `StatusHandler` bypasses that mechanism entirely.
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) unconditionally writes a `CommitStatus` row (`statuses.replicate_from_github!`) for the found commit, regardless of which org authenticated the webhook.

Exploit flow: Attacker controls org A (with its own valid `webhook_secret`, e.g. a hooked GitHub org they administer). They observe a public commit `sha` belonging to a stack under org B (shas are visible via GitHub PRs, commits API, etc.). They POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{"sha": "<org-B-commit-sha>", "state": "success", "repository": {"owner": {"login": "org-A"}, "full_name": "irrelevant"}}
```
signed with org A's secret. `verify_signature` succeeds (org A's secret matches its own payload bytes). `StatusHandler` finds the `Commit` row for org B's sha and writes a forged `success` status to it, independent of `repository.full_name`.

Existing guards do not prevent this: `verify_signature` authenticates only the source org, not the sha's owning stack; `drop_unhandled_event` only checks the event type is handled; `ExplicitParameters` schema only validates field types/presence, not repository ownership; there is no model validation tying a `CommitStatus` write to the authenticating organization.

### Impact Explanation
Any attacker who has (or creates) a Shipit-integrated GitHub organization with a configured `webhook_secret` can forge CI status for commits belonging to any other tenant's stack, since commit shas are observable/guessable from public PRs/commits. Forged `success` statuses can make blocked or CI-gated commits appear deployable (`Commit#deployable?`, `stack.schedule_merges`), potentially causing an unauthorized/unsafe deploy or merge for a stack the attacker never authenticated against — a cross-repository/cross-tenant write matching the "payload for one repository mutating another's stack/commit" Critical category. This is repeatable against any target sha and any target stack, and requires no interaction from org B.

### Likelihood Explanation
Preconditions: attacker must control (own or register) at least one org with a configured `webhook_secret` in the host Shipit deployment — feasible in any multi-tenant/self-service Shipit deployment where organizations can be onboarded. The target commit sha must exist in the `commits` table under some stack (true for any tracked branch/PR commit) and shas are typically discoverable via public GitHub activity. No GitHub, Shipit, or victim-org secrets are required for the target; only the attacker's own org secret. This is a low-cost, fully repeatable HTTP POST attack.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the stacks resolved from the authenticated `repository_name`/`stacks` (as `Handler` already provides), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack: stacks)`, so a status update can only be applied to commits belonging to stacks under the organization that authenticated the webhook.

### Proof of Concept
Minitest plan (integration test under `test/controllers/webhooks_controller_test.rb` or `test/models/webhooks/handlers/status_handler_test.rb`):
1. Create org/stack A (`stack_a`, secret `secret_a`) and org/stack B (`stack_b`, secret `secret_b`) with a `commit_b` belonging to `stack_b`.
2. Build a `status` webhook payload: `{sha: commit_b.sha, state: 'success', repository: {owner: {login: stack_a.repository.owner}, full_name: stack_a.repository.full_name}}`.
3. Sign the raw JSON body with `secret_a` (org A's real secret) and POST to `/webhooks` with `X-Github-Event: status`.
4. Assert response is `200 OK` (signature verified against org A).
5. Assert equality that should hold but doesn't before fix: `commit_b.stack.repository.owner == stack_a.repository.owner` — false, proving cross-tenant mismatch.
6. Assert `commit_b.reload.statuses.exists?(state: 'success')` is `true` — a status was written to org B's commit despite the request only having been authenticated for org A, demonstrating the vulnerability.
7. After applying the recommended fix (scoping lookup to `stacks`), re-run the same request and assert `commit_b.reload.statuses.exists?(state: 'success')` is `false`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```
