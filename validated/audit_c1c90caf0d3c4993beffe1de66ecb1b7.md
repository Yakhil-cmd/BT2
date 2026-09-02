### Title
Signature verification keys off `repository.owner.login` while the actual write target is derived from `repository.full_name`, allowing cross-organization/cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) out of the **unverified** JSON body, then verifies the raw body against that org's secret. Once verification passes, the event is dispatched to handlers (e.g. `PushHandler`) which determine the actual `Stack`/`Repository` to mutate using a **different** field of the same payload: `repository.full_name` (via `Handler#repository_name` / `Repository.from_github_repo_name`). Because the payload is attacker-authored (any party who knows *any* configured org's `webhook_secret` can produce a validly-signed body), nothing forces `repository.owner.login` and `repository.full_name`'s owner segment to agree. This breaks the trust binding "organization whose secret authenticated the request" == "repository that gets written to."

### Finding Description
In a multi-organization Shipit deployment (`config/secrets.development.example.yml` / `test/dummy/config/secrets_double_github_app.yml` document this supported mode with independent `webhook_secret` per org), each configured GitHub organization has its own webhook secret, known to whoever set up that org's GitHub App (potentially a different, unrelated tenant/customer than the target repository's owner).

The signature check: [1](#0-0) 
picks the HMAC key via `repository_owner`, itself read straight from the unverified body: [2](#0-1) 

Once `verify_signature` passes, `create` dispatches the same raw JSON to handlers: [3](#0-2) 

Handlers resolve the target repository/stack from a *different* JSON field, `repository.full_name`: [4](#0-3) 

For example `PushHandler`, used to trigger `sync_github` (which updates commit/branch state driving deploys): [5](#0-4) 

Because `repository.owner.login` (used to select the trusted secret) and `repository.full_name` (used to select the mutated repository) are independent, attacker-controlled strings inside the same JSON body, an attacker who legitimately knows the webhook secret for Org A (their own onboarded org) can craft a payload where `repository.owner.login = "OrgA"` but `repository.full_name = "OrgB/victim-repo"`. The signature is computed over the full raw body using OrgA's secret and will verify successfully, yet the `PushHandler`/other handlers will act against `OrgB`'s stack, since `Repository.from_github_repo_name` matches purely on `full_name`.

Equality that should hold but is broken:
`organization authenticated by verify_signature (repository.owner.login)` == `organization/repository actually mutated by handlers (repository.full_name)`

### Impact Explanation
This allows an attacker who controls one legitimate GitHub App integration (i.e., knows one org's `webhook_secret`) to forge webhook events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) that are accepted as authentic and dispatched against an unrelated stack/repository they do not own. Depending on the handler this can:
- trigger `GithubSyncJob`/`sync_github` on a victim stack (`PushHandler`), influencing what Shipit believes is the head-of-branch state used to gate/queue deploys,
- inject fabricated CI `status`/`check_suite` results for a victim commit (`StatusHandler`/`CheckSuiteHandler`), which the merge queue and deploy gating (`StatusChecker`, `required_statuses`) rely on to decide whether a commit is safe to merge/deploy,
- forge `membership` events for a team the attacker does not administer.

Because CI status / branch head state can gate automatic merges and deploys, this can be leveraged toward an unauthorized deploy/merge on a repository the attacker does not control — matching the Critical bucket ("unauthorized deploy, rollback or merge") or at minimum the High bucket (cross-tenant write to stack/task state without authorization).

### Likelihood Explanation
The webhook endpoint is unauthenticated by design (no session or `ApiClient` token required) — the only gate is the HMAC signature. The only precondition is that the attacker knows a `webhook_secret` for *some* org configured in the Shipit instance (a very plausible situation in the documented multi-org configuration mode, where different tenants each configure and know their own app's webhook secret). No repository write access, session, or privileged Shipit account is required to exploit this against the *victim* repository — likelihood is Medium-to-High in any multi-tenant deployment.

### Recommendation
Cryptographically bind the signature check to the same repository/organization value the handlers use to select the write target. Concretely:
- Use `repository.full_name`'s owner segment (not a separate `repository.owner.login`/`organization.login` field) to select the `Shipit.github(organization:)` used for `verify_webhook_signature`, or
- After verifying, re-derive `repository_owner` strictly from `repository.full_name` and reject (422) if it disagrees with the org used to validate the signature.

### Proof of Concept
1. Deploy Shipit with two configured GitHub orgs, e.g. `OrgA` (attacker-controlled, webhook_secret known to attacker) and `OrgB` (victim, unrelated stack `OrgB/victim-repo`).
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` → `"OrgA"`, fetches OrgA's `webhook_secret`, and the signature validates successfully.
5. `PushHandler#process` runs `Repository.from_github_repo_name("OrgB/victim-repo")` and calls `sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stack, despite the request never being authenticated for OrgB. [6](#0-5) [4](#0-3) [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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
