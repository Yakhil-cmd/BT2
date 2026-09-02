### Title
Cross-organization webhook forgery via repository-owner/repository-name mismatch - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which HMAC `webhook_secret`) to verify a webhook against based on `repository.owner.login` (falling back to `organization.login`), but the event handlers that actually act on the payload key off a *different* field, `repository.full_name`, to locate the `Repository`/`Stack`/`Commit` records to mutate. In a multi-organization Shipit deployment (`config/secrets.yml` with one `github:` section per org, as documented in `docs/setup.md`), these two fields are never checked for consistency.

### Finding Description
`verify_signature` picks the app/secret to validate against like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the unverified, attacker-supplied JSON body (`params.dig('repository', 'owner', 'login')`), and `Shipit.github(organization: repository_owner)` returns the GitHub App configuration (and `webhook_secret`) registered for *that* organization name.

Once the signature check passes, the full, unmodified payload is dispatched to every handler registered for the event: [3](#0-2) 

But the handlers resolve the target `Repository`/`Stack`/`Commit` using a *different* field of the same payload — `repository.full_name` — via `Handler#repository_name` / `Handler#stacks`: [4](#0-3) 

For example `PushHandler` and `StatusHandler` both act purely on payload contents keyed by commit sha / branch, with no cross-check against `repository.owner.login`: [5](#0-4) [6](#0-5) 

**Broken binding:** organization authenticated (`repository.owner.login`, used to pick the `webhook_secret`) ≠ repository actually written (`repository.full_name`, used by the handler to find records). Nothing in `WebhooksController` or `Handler` enforces that `repository.full_name` belongs to the organization whose secret validated the signature.

**Exploit path:** an attacker who administers (or is simply granted webhook access to) any single GitHub organization/repository that is configured on the *same* shared Shipit instance (e.g., `attacker-org`, per `docs/setup.md`'s "Using Multiple GitHub Applications" setup) knows that org's `webhook_secret` (visible to any org admin when creating/inspecting the GitHub App/webhook). They can then POST a forged webhook to `/webhooks` with:
- `X-Github-Event: status` (or `push`)
- `repository.owner.login = "attacker-org"` (so `verify_signature` selects `attacker-org`'s known secret)
- `X-Hub-Signature` computed correctly with that secret
- `repository.full_name = "victim-org/victim-repo"`, and an arbitrary `sha`/`state: "success"`

Because `repository_owner` and `repository_name` are extracted from different, uncorrelated fields, this payload passes signature verification and is then processed as if it legitimately originated from `victim-org`.

### Impact Explanation
Via `StatusHandler`, the attacker can inject arbitrary GitHub commit statuses (`state: success`, forged `context`) onto any commit sha tracked by any stack across the whole Shipit instance, without ever having credentials for that organization/repository. This can satisfy `ci.require` checks and `StatusChecker` used both for stack deploy gating and pull-request merge gating, potentially causing an unreviewed/malicious commit to be treated as CI-passed, unlocking an unauthorized deploy or merge for a repository the attacker has no legitimate access to. Via `PushHandler`, the attacker can also trigger `sync_github`/`GithubSyncJob` against arbitrary victim stacks. This crosses the "unauthorized deploy" / "cross-repository writes" bar defined as Critical impact.

### Likelihood Explanation
This requires the target Shipit instance to be configured for multiple GitHub organizations (a documented, supported configuration in `docs/setup.md`) and requires the attacker to control/administer at least one of those organizations' GitHub Apps (to know its `webhook_secret`) while targeting a different, unrelated organization hosted on the same instance. This is a realistic multi-tenant scenario for shared Shipit deployments and needs no session, `ApiClient` token, or GitHub credentials for the victim org — only knowledge of a sibling org's own webhook secret, which the attacker legitimately possesses for their own org.

### Recommendation
In `WebhooksController#verify_signature` / `Handler`, verify that the organization/owner used to select the webhook secret matches the organization implied by `repository.full_name` (or `organization.login`) that the handler will actually act upon, rejecting the webhook (422) on mismatch. Alternatively, resolve the target `Repository` first, derive its owning organization, and use that organization's configuration for verification instead of trusting `repository.owner.login` independently from `repository.full_name`.

### Proof of Concept
1. Configure two orgs in `config/secrets.yml`: `attacker-org` (attacker knows `webhook_secret_A`) and `victim-org` (uses `webhook_secret_B`), both onboarded to the same Shipit instance, per `docs/setup.md`.
2. Attacker crafts a JSON body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {
     "owner": { "login": "attacker-org" },
     "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(webhook_secret_A, body)>` using their own known `webhook_secret_A`.
4. POST to `/webhooks` with header `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner = "attacker-org"`, fetches `attacker-org`'s config, verifies successfully.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, applying a forged "success" status to the victim commit — despite the request never being signed by `victim-org`'s secret.

Note: I was unable to fully inspect `Commit#create_status_from_github!` and `Stack#deployable?`/CI-gating logic (`app/models/shipit/commit.rb`, `app/models/shipit/stack.rb`) within the available search budget to confirm the exact downstream deploy-gating mechanics; this should be verified by a background agent with full file access before remediation.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
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
