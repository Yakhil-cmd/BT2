### Title
Webhook signature verification binds only the "org that authenticated", not the repository/commit the event content is allowed to touch — cross-organization commit-status forgery leading to unauthorized deploy/merge - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects a `webhook_secret` using an org name taken from the same untrusted payload it is about to verify, and once *any* configured organization's secret validates the payload, downstream handlers (in particular `StatusHandler`) apply the event to state (commits/statuses) with no re-check that the event actually originates from the repository/org that owns that state. This mirrors the reported Sake bug class: the documentation/contract of "verifying the webhook" implies the whole trust boundary (org ↔ repository ↔ commit) is enforced, but the code only enforces "some configured org's secret matches", not "the org that signed this request owns the repository/commit being mutated".

### Finding Description
`Shipit::WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) derives the signing organization purely from the untrusted JSON body: [1](#0-0) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

This `repository_owner` is used only to pick *which configured GitHub App's `webhook_secret`* to HMAC-verify against: [2](#0-1) 

Because Shipit is designed to host multiple GitHub organizations in a single instance (see `config/secrets.development.shopify.yml`, which configures multiple orgs each with its own `webhook_secret`), the signature check equality that actually holds is:

`HMAC(payload, secret_of(attacker-chosen repository_owner)) == signature`

not `HMAC(payload, secret_of(the org that legitimately owns the resource being mutated)) == signature`.

Once this check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs unscoped handlers on the raw JSON. `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb) does not re-derive or re-check any owning organization/repository at all — it looks up commits **globally by SHA**: [3](#0-2) 

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

`Commit#create_status_from_github!` → `add_status` writes a new `Status` record, recomputes `Commit#status`, and this directly feeds `Commit#deployable?` (app/models/shipit/commit.rb:227-229) and `Hook.emit(:deployable_status, ...)`, and can trigger `stack.schedule_merges` (line 383) which processes the merge queue (`ProcessMergeRequestsJob` → `MergeRequest#merge!`, app/models/shipit/merge_request.rb:164-191) using this forged status as evidence CI passed.

**Attack path**: an attacker who is able to obtain/derive the `webhook_secret` for *one* organization configured on the shared Shipit instance (e.g., they administer that org's GitHub App/webhook settings — a capability scoped only to that org, not to Shipit itself) can craft a signed webhook body of event type `status` with:
- `repository.owner.login` = the org they control (so `verify_signature` picks and matches their own secret),
- `sha` = the SHA of a commit belonging to a **different** organization's stack (SHAs are public/discoverable via GitHub or the Shipit UI),
- `state` = `"success"`, `context` = a CI context required by the victim stack's `shipit.yml` `ci.require`/`merge.require`.

The HMAC signature is valid (it was computed with the attacker's own legitimate secret over their own crafted body), so `verify_signature` passes, and `StatusHandler` blindly attaches a fabricated "green" status to the victim commit, satisfying `Commit#deployable?` and merge-queue CI requirements for a repository the attacker has no access to.

This is the "organization that authenticated versus the repository that is written" binding called out in scope: the signature only proves *an* org's secret was used, not that *that* org is the one whose resources the payload is allowed to mutate.

### Impact Explanation
This allows an attacker to forge passing CI/commit statuses for commits belonging to a repository/organization they do not control, as long as they control (or have leaked) any single organization's webhook secret configured on the same Shipit deployment. Forged "success" statuses satisfy `Commit#deployable?` and merge-queue `required_statuses` checks, which can lead to an **unauthorized deploy** (a deploy that should have been blocked by CI, `stack.trigger_deploy`) or an **unauthorized merge** via the merge queue (`MergeRequest#merge!`, which itself calls the GitHub API using Shipit's own `GITHUB_TOKEN`-equivalent credentials to merge a PR). This matches the Critical bucket ("unauthorized deploy, rollback or merge") defined in scope.

### Likelihood Explanation
Exploitability requires the attacker to know a `webhook_secret` valid for *any* organization configured on the Shipit instance — a realistic condition in shared/multi-tenant Shipit deployments where many orgs (with different trust levels/admins) share one Shipit instance and each org's webhook secret is managed independently by that org's own GitHub App/organization admins. No Shipit session, `ApiClient` token, or repository write access on the *victim* repository is required — only push/webhook-signing capability on an unrelated, lower-trust organization sharing the instance, and knowledge of a target commit SHA (which is public). The victim-side commit SHA and required CI context names are discoverable from the public GitHub repository or the Shipit UI.

### Recommendation
- After signature verification, re-validate that `repository.full_name` / `repository.owner.login` used to resolve the `Commit`/`Stack` in each handler actually corresponds to the organization whose secret validated the signature (i.e., bind the verified org to the resource being mutated, not just to secret selection).
- In `StatusHandler` (and any other handler that looks up records without scoping to `repository_name`), scope the lookup through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and verify it matches the org used for signature verification, rather than querying `Commit` globally by `sha`.
- Consider deriving the "signing org" strictly from `repository.full_name`'s owner segment (single source of truth) rather than independently from `repository.owner.login`/`organization.login`, closing any divergence between the two payload fields.

### Proof of Concept
1. Shipit instance is configured (per `config/secrets.development.shopify.yml`) with two organizations, `orgA` and `orgB`, each with its own `webhook_secret`. Attacker administers `orgA`'s GitHub App/webhook settings (legitimate for `orgA` only) and thus knows `orgA`'s `webhook_secret`.
2. Attacker finds a commit SHA `deadbeef...` belonging to a stack under `orgB` (public repo, or from Shipit's public commit page) that requires CI context `ci/circleci` before deploy/merge.
3. Attacker builds a JSON body:
```json
{
  "repository": {"owner": {"login": "orgA"}, "full_name": "orgA/attacker-repo"},
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/circleci",
  "created_at": "2026-09-01T00:00:00Z"
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(orgA_webhook_secret, body)` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner` = `"orgA"`, fetches `orgA`'s config, verifies the HMAC — passes.
6. `StatusHandler#process` runs `Commit.where(sha: "deadbeef...")`, finds the `orgB` commit (owned by a stack the attacker has no access to), and calls `create_status_from_github!`, injecting a forged "success" `ci/circleci` status.
7. If this satisfies `orgB` stack's `ci.require`/`merge.require`, the commit becomes `deployable?` or eligible for merge-queue processing, enabling an unauthorized deploy or PR merge on `orgB`'s repository — a cross-organization trust boundary break the attacker should not have been able to cross.

Note: I was not able to fully trace every downstream consumer of forged statuses (e.g., exact continuous-deployment auto-trigger conditions) within the available index; a Devin session with full repository access would be needed to confirm the complete downstream deploy/merge trigger chain end-to-end.

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
