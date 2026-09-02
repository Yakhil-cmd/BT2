## Finding

### Title
Webhook `status` events forge CI check results on arbitrary tracked commits, bypassing deploy/merge gating - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The webhook signature check authenticates *which GitHub organization* sent a webhook, but `StatusHandler` never verifies that the `status` event's `repository` matches the repository owning the commit it updates. It matches purely by commit SHA across the entire instance, so a `status` webhook that is validly signed for one tracked organization can write a fake "success" status onto a commit belonging to a completely different, unrelated stack/repository, letting an attacker satisfy required CI checks (`ci.require` / `merge.require`) and trigger an unauthorized deploy or merge queue merge.

### Finding Description
`WebhooksController#verify_signature` derives the signing organization solely from the payload's `repository.owner.login` (falling back to `organization.login`) and validates the HMAC against that organization's configured `webhook_secret`: [1](#0-0) 

This only proves "this request was signed by GitHub for organization X." It says nothing about which repository's data the payload is entitled to affect. However, `StatusHandler#process` ignores the `repository` field entirely and resolves the target purely by matching the reported SHA against *every* commit tracked by the instance: [2](#0-1) 

The created status is attached using the *actual* commit's own `stack_id` (not anything derived from the webhook payload), so it directly participates in that stack's real CI/merge gating: [3](#0-2) 

This breaks the intended binding: `organization authenticated by signature == repository whose data is written`. In reality the engine enforces only `organization authenticated by signature == organization that owns *some* GitHub repo that sent this webhook`, and then writes to *any* commit anywhere in the instance whose SHA happens to match, regardless of which stack/repository/organization that commit actually belongs to.

GitHub's Commit Status API (`POST /repos/{owner}/{repo}/statuses/{sha}`) does not require the `{sha}` to correspond to a commit that exists in `{owner}/{repo}` — it will happily create/deliver a status (and the accompanying webhook) for any 40-hex-character SHA, even one copied from a public commit in an entirely different repository. Because `StatusHandler` performs no repository check, this is directly exploitable.

### Impact Explanation
An attacker who administers (or has push access sufficient to set commit statuses in) any single GitHub organization/repository tracked by this Shipit instance can:
1. Discover the target commit SHA of a PR/branch in a victim stack tracked by a *different* organization (commit SHAs are frequently public, e.g., via the GitHub UI/API for public repos or through a merge request URL exposed by Shipit itself).
2. Use their own repository's write access to call GitHub's Statuses API and set an arbitrary `context`/`state: success` status on that SHA.
3. GitHub delivers a legitimately-signed `status` webhook to Shipit for the attacker's own organization.
4. `WebhooksController#verify_signature` passes because the signature is valid for the attacker's org.
5. `StatusHandler` finds the victim's real `Commit` (matched only by SHA) and records the forged "success" status against it, associated with the victim's real stack.
6. This forged status can satisfy `ci.require` / `merge.require` contexts used by `MergeRequest#all_status_checks_passed?`, letting `ProcessMergeRequestsJob` auto-merge a pull request in the merge queue, or unblock a manual deploy that depends on required statuses.

This maps to the Critical impact category "unauthorized deploy, rollback, or merge," since the attacker crosses an organization/repository trust boundary that the signature check is supposed to enforce.

### Likelihood Explanation
This requires only that the attacker control (or have status-write access to) at least one GitHub organization/repository already onboarded to the same multi-tenant Shipit instance — no Shipit credentials, `ApiClient` tokens, or webhook secrets need to be known or stolen. Any Shipit deployment tracking repositories/organizations with different trust levels (a very common multi-tenant setup, as documented in `config/secrets.development.shopify.yml` supporting multiple `github:` orgs) is exposed.

### Recommendation
`StatusHandler` (and ideally `Handler#stacks`/`repository_name` usage generally) must scope the lookup to the repository declared in the webhook payload, and cross-check that repository against the organization that authenticated the request. Concretely:
- Change `StatusHandler#process` to resolve commits only within `stacks` (repository-scoped, as `PushHandler`/`CheckSuiteHandler` already do) rather than a global `Commit.where(sha: params.sha)`.
- In `WebhooksController#verify_signature`, additionally assert that the `repository.owner.login` used to select the signing organization actually corresponds to the repository referenced in the event payload for handlers that identify records by fields other than repository (defense in depth).

### Proof of Concept
1. Attacker has write access to `attacker-org/some-repo`, which is a legitimate org registered with this Shipit instance (own `webhook_secret`, own GitHub App).
2. Attacker finds `victim-org/victim-repo`'s open PR head SHA `abc123...` (tracked by a different stack in the same Shipit instance), which requires a CI context named `ci/required`.
3. Attacker calls `POST /repos/attacker-org/some-repo/statuses/abc123...` with `{"state":"success","context":"ci/required"}` using their own repo's token — GitHub accepts this even though `abc123...` isn't a commit in `some-repo`.
4. GitHub sends a `status` webhook to Shipit, signed with `attacker-org`'s webhook secret, containing `sha: abc123...`, `repository.full_name: attacker-org/some-repo`.
5. `WebhooksController#verify_signature` succeeds (signature is valid for `attacker-org`).
6. `StatusHandler#process` runs `Commit.where(sha: 'abc123...')`, finds the victim's real commit belonging to `victim-org/victim-repo`'s stack, and creates a `success` status for `ci/required` on it.
7. If this was the only missing/failing required status, `MergeRequest#all_status_checks_passed?` now returns true for the victim's pending merge request, and `ProcessMergeRequestsJob` merges it — an unauthorized merge triggered entirely from an unrelated organization's webhook credentials.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
