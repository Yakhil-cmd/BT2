Found the mismatch that maps to the report's "hardcoded/wrong field consumed vs. the field actually used to bind trust" bug class.

### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while stack targeting is keyed off the unrelated `repository.full_name` field, breaking the org-secret-to-repository binding - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/org config (and therefore which `webhook_secret`) to verify the request against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. Once the HMAC is accepted for that organization, the *same* raw payload is handed unmodified to the event handlers, but the handlers determine which `Stack`/`Repository` to act on using a completely different field: `payload.dig('repository', 'full_name')` in `Shipit::Webhooks::Handlers::Handler#repository_name`.

### Finding Description
In a multi-organization Shipit deployment (`Shipit.github_organizations`, documented in `README.md`), each organization has its own `webhook_secret`. `WebhooksController#verify_signature` resolves the app/secret to use via: [1](#0-0) 
using `repository_owner`: [2](#0-1) 

The verification equality that is actually enforced is:
`HMAC(secret_for(payload.repository.owner.login), raw_body) == X-Hub-Signature`

But the equality that determines *what gets acted upon* is unrelated to `owner.login`; every handler resolves the target repository via `Handler#repository_name`: [3](#0-2) 

Since the HMAC only proves knowledge of the secret belonging to whatever organization is *declared* in `repository.owner.login`, and the handler-side identification of the affected stack is bound to the independent `repository.full_name` field of the same JSON body, an attacker who legitimately controls a repository/webhook secret for `OrgA` (any repository admin under `OrgA` can see/rotate that secret in their own GitHub App/webhook settings for events on their own repos) can build a raw POST body where:
- `repository.owner.login = "OrgA"` (drives secret selection → passes verification with the secret they know)
- `repository.full_name = "OrgB/victim-repo"` (drives which `Stack` receives the sync/status/check-run action)

Because the whole raw body (including both fields) is signed with the *attacker's own* HMAC computation using the `OrgA` secret they legitimately possess, `verify_webhook_signature` succeeds, and the resulting `push`/`status`/`check_suite` handler acts on `OrgB`'s stack using attacker-chosen data (e.g., `PushHandler` triggers `stack.sync_github(expected_head_sha: params.after)` for any stack matching the given branch under `OrgB`, and `StatusHandler`/`CheckSuiteHandler` let the attacker forge arbitrary commit statuses / check-run refresh triggers for commits under `OrgB`'s stacks): [4](#0-3) [5](#0-4) 

This is directly analogous to the Gondi finding: there, the value used inside a security-relevant computation (`_lidoData.lastTs`) was disconnected from the value that should have governed it (the real `block.timestamp`), silently deflating the enforced `aprBps` check. Here, the value used to select the verifying secret (`repository.owner.login`/`organization.login`) is disconnected from the value that governs which stack/repository the verified payload is allowed to affect (`repository.full_name`), silently letting a valid-looking signature authorize actions on a different organization's data.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" binding explicitly listed in scope. Concretely, an attacker who is a legitimate collaborator/admin on any repository under one GitHub organization onboarded to a multi-org Shipit instance can forge status/check-run/push-sync webhook events that are attributed to a *different* organization's stacks, causing:
- Forged/fake commit `status` entries on arbitrary commits of another org's stack (`StatusHandler`), which can be leveraged to make an otherwise-blocked commit appear CI-green and pass `deployable?`/`merge_status` checks — enabling an unauthorized deploy or PR merge under `MergeRequest#merge!`/`ProcessMergeRequestsJob`.
- Forced re-sync (`PushHandler` → `stack.sync_github`) of another org's stack with an attacker-chosen `expected_head_sha`, and forced check-run refresh (`CheckSuiteHandler`) for arbitrary commit shas.

This satisfies the "unauthorized deploy, rollback, or merge" / "unauthenticated write of stack state" style High/Critical impact bar, since none of the excluded credentials (Shipit session, ApiClient token, `api_clients_secret`, GitHub App private key, repository write access *on the victim repo*, TLS interception) are required — only knowledge of a webhook secret the attacker legitimately possesses for their *own*, unrelated organization.

### Likelihood Explanation
This only manifests when a Shipit instance is configured with the multi-organization `github` secrets schema (each org keyed with its own `webhook_secret`), which is a documented, supported configuration (`README.md`/`docs/setup.md`). In the single-organization configuration (`github_default_organization.nil?`), there is only one secret so the org-selection step is moot and this specific cross-org write does not apply, though the underlying disconnect between the field used for secret selection and the field used for repository targeting is still architecturally present. Exploitation requires the attacker to already have legitimate access to at least one onboarded organization (to learn/derive its `webhook_secret` via their own GitHub App installation) — this is a materially lower bar than compromising the victim org.

### Recommendation
Do not use attacker-controlled payload fields to select the verification secret independent of what the handlers use to select the target repository. Concretely:
- After signature verification succeeds using `repository_owner`, re-derive the "owning organization" from the *same* field the handlers use for stack lookup (`repository.full_name`'s owner segment, or `Repository.from_github_repo_name`) and require it to match the organization whose secret validated the signature; reject (422) on mismatch.
- Alternatively, bind webhooks to a known repository/organization out-of-band (e.g., verify the resolved `Stack`/`Repository`'s configured owner equals the organization whose secret was used) before invoking any handler.

### Proof of Concept
1. Deploy Shipit with the multi-org `github` secrets schema, onboarding `OrgA` (attacker-controlled webhook secret known to the attacker via their own GitHub App settings) and `OrgB` (victim, has a Shipit `Stack` for `OrgB/victim-repo`).
2. Craft a raw JSON body for a `status` event:
```json
{
  "sha": "<victim commit sha under OrgB/victim-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>` using the attacker's own known `OrgA` secret.
4. POST to `/webhooks` with header `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `OrgA`'s app/secret, and the HMAC matches → request passes verification.
6. `StatusHandler#process` resolves the target via `payload.dig('repository', 'full_name')` = `"OrgB/victim-repo"`, and creates a forged successful status on the victim's commit, even though the attacker has no relationship to `OrgB`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
