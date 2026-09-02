### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but handlers act on the unrelated `repository.full_name` field, allowing cross-organization/cross-repository writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to validate the HMAC signature against using `repository.owner.login` (or `organization.login`) taken from the *unverified* JSON body. Once the signature check passes, every event handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `PullRequest::OpenedHandler`, etc.) resolves the target `Repository`/`Stack` using a completely different, independently attacker-controlled field of the same body: `repository.full_name`. The HMAC signature covers the raw body bytes, not any binding between these two fields, so a payload can be crafted where the "owner" used to pick the secret and the "full_name" used to pick the target repo point to different organizations.

### Finding Description
In a multi-organization Shipit deployment, `Shipit.github(organization:)` maps each configured GitHub organization to its own `webhook_secret` (`lib/shipit.rb`, `github_app_config`). `WebhooksController#verify_signature` computes: [1](#0-0) 
using [2](#0-1) 
i.e. the organization used to select which secret verifies the HMAC signature is read directly from the JSON body's `repository.owner.login`/`organization.login`, before any authenticity has been established.

After the signature check passes (proving only that *some* configured organization's secret produced this HMAC), `create` re-parses the same raw body and dispatches it to handlers: [3](#0-2) 

Every handler determines the affected `Repository`/`Stack` using an unrelated field, `repository.full_name`, not `repository.owner.login`: [4](#0-3) [5](#0-4) [6](#0-5) 

Because `owner.login` (used for auth) and `full_name` (used for the write target) are two independent JSON fields inside the same signed body, an attacker who can get GitHub to deliver a webhook signed with organization A's secret (e.g. any push/status/check_suite event naturally triggered on any repository that belongs to organization A and has the Shipit webhook/app installed) can forge the body so that `repository.owner.login` = `"org-a"` while `repository.full_name` = `"org-b/target-repo"`. The signature still validates (it was computed over org A's secret and the raw bytes as delivered), but the handler acts on `org-b/target-repo`, a repository/organization the attacker never authenticated for.

This is the same class of bug as the report: a value that is *used* by the finalization/authorization logic (`finalBlockNumber`/organization) is never checked for consistency against the value that is *actually acted upon* (submitted data/full_name), letting an authenticated party redirect the effect of their authenticated action onto data they don't control.

### Impact Explanation
This breaks the equality "organization that authenticated == repository that is written," letting a webhook legitimately signed for organization A affect stacks belonging to organization B. Depending on handler, this enables:
- Triggering `GithubSyncJob`/commit ingestion and stack state changes (`PushHandler`) on a foreign repository's stacks.
- Injecting/forging commit statuses on a foreign repository's commits (`StatusHandler`) — `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }`.
- Creating/archiving/unarchiving review stacks and pull-request-driven provisioning for a foreign repository (`PullRequest::OpenedHandler`, `ReviewStackAdapter`).
- Scheduling check-run refreshes for foreign repositories (`CheckSuiteHandler`).

This matches the "cross-repository writes" Critical impact category, since it allows unauthorized state mutation on a repository/organization outside the one whose credential actually produced the signature.

### Likelihood Explanation
Exploitability requires the attacker to be able to make GitHub deliver (or replay) a webhook payload whose raw body they fully control while it is still signed by organization A's secret — practically, this means the attacker has push/webhook-triggering ability on at least one repository under organization A that has the Shipit GitHub App/webhook installed (a normal, low-privilege event source, not the target org B they wish to affect). No access to organization B, its `webhook_secret`, or a Shipit account is required. The relevant fields (`repository.owner.login` vs `repository.full_name`) are both plain JSON attributes with no cryptographic binding to each other, so the forgery itself is simple — the only requirement is a genuine signed delivery from org A, which is routine.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), verify that the organization whose secret validated the signature matches the owner embedded in `repository.full_name` used by the handlers, e.g., require `repository.full_name.split('/').first.casecmp(repository_owner).zero?` before dispatching to handlers, or derive `repository_owner` and the handler's repository lookup from the exact same parsed field so no two independent attacker-controlled fields can diverge.

### Proof of Concept
Assume a Shipit instance configured with two organizations in `secrets.github`: `org-a` (secret `S_A`) and `org-b` (secret `S_B`), each with the Shipit GitHub App/webhook installed on their own repos.

1. Attacker has ordinary push access to `org-a/some-repo` (webhook signed with `S_A` on every push).
2. Attacker crafts (or has GitHub deliver, then intercepts/re-sends with a controlled body — or simply constructs the push event body content themselves since they control the pushed ref/commit metadata) a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/target-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, body)`.
4. `WebhooksController#verify_signature` computes `repository_owner = "org-a"`, loads `Shipit.github(organization: "org-a")`, and the HMAC matches → request is accepted.
5. `PushHandler#process` calls `stacks` → `Handler#stacks` → `Repository.from_github_repo_name("org-b/target-repo")`, resolving `org-b`'s stack and invoking `stack.sync_github(expected_head_sha: "deadbeef...")`, causing Shipit to sync/ingest attacker-chosen commit data for `org-b/target-repo` despite the request only having been authenticated for `org-a`.

**Uncertainty**: this analysis assumes a multi-organization `secrets.github` configuration (distinct `webhook_secret` per org) is in use, which is a supported and documented mode (`lib/shipit.rb#github_app_config`, `github_organizations`) but not necessarily the default single-org setup; in a single-org deployment this specific cross-org variant collapses (only one secret exists), though the underlying design flaw — signature verification target chosen from an unverified field, decoupled from the field used for the actual write — remains present in the code.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
