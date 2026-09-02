Found the analog. The verified binding in `WebhooksController#verify_signature` is keyed on `repository.owner.login` (or `organization.login`) to select which GitHub App/organization secret validates the HMAC, but the handlers that act on the payload (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolve the target `Stack`/`Repository` using the separate `repository.full_name` field, which is never covered by that same lookup and is not cross-checked against the verified owner.

### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while state-mutating handlers act on the unverified `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). [1](#0-0)  It then verifies `X-Hub-Signature` against the raw body using that organization's `webhook_secret`. [2](#0-1)  Once verified, the same raw body is dispatched unmodified to event handlers, e.g. `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, all of which derive the target `Stack` via `Handler#repository_name`, reading `payload.dig('repository', 'full_name')` and looking it up with `Repository.from_github_repo_name`. [3](#0-2) [4](#0-3)  The signature check binds to `repository.owner.login`; the write binds to `repository.full_name`. These two fields are independent, attacker-controlled JSON keys inside the same unsigned-in-parts payload, and nothing enforces `full_name.split('/').first == repository.owner.login`.

### Finding Description
The vulnerability breaks the equality:
`organization whose webhook_secret authenticates the request == repository owner that the handler subsequently writes to`

An attacker who controls (owns/administers) any GitHub organization/repo that has installed a Shipit-connected GitHub App (i.e. knows that org's `webhook_secret`, a normal, unprivileged capability for an org admin of their *own* org) can:
1. Compute a valid `X-Hub-Signature` for a JSON body where `repository.owner.login` = their own org (`attacker-org`) — this passes `verify_signature` because `Shipit.github(organization: 'attacker-org')` resolves to the attacker's own configured `GitHubApp`/secret. [5](#0-4) 
2. Set `repository.full_name` in the same body to `"victim-org/victim-repo"`, a repository actually tracked by Shipit under a *different*, victim organization's stack.
3. Send this to `/webhooks` with `X-Github-Event: push` (or `status`, `check_suite`, `pull_request`, etc.).

`verify_signature` never inspects `full_name`, only `repository.owner.login`/`organization.login`. [1](#0-0)  After the 422/head checks pass, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs the real handlers against the full unmodified `params` hash, including the attacker-set `full_name`. [6](#0-5)  `PushHandler#process` then finds the victim's non-archived stacks matching the pushed branch and calls `stack.sync_github(expected_head_sha: params.after)` with an attacker-supplied `after` SHA — a resync/re-sync-trigger cross-organization action the attacker's own org credentials were never authorized to perform against the victim repository. [7](#0-6) 

### Impact Explanation
This is a cross-repository/cross-organization write: an entity that legitimately authenticates only as `attacker-org` (via its own `webhook_secret`) can force Shipit to process events (sync GitHub state, create commit statuses via `StatusHandler`, trigger `RefreshCheckRunsJob` via `CheckSuiteHandler`, create/remove team memberships via `MembershipHandler`) scoped to `victim-org/victim-repo`, which it has no relationship to. Depending on handler, this can drive spurious `Stack#sync_github` calls, forged commit statuses that gate CI-based deploy checks, or bogus check-run refreshes on a victim's tracked repository — state corruption/pollution across organizational trust boundaries that the per-organization webhook secret model is meant to prevent.

### Likelihood Explanation
High. It requires no privileged Shipit credentials, only administration of any GitHub organization that itself has a Shipit-connected GitHub App/webhook secret (a routine, unprivileged setup many orgs may have if Shipit is run multi-tenant across organizations, which the engine explicitly supports via the multi-org `github:` config shown in `config/secrets.development.example.yml`). The payload is fully attacker-authored JSON; only the signature computation depends on a secret the attacker legitimately possesses for their own org.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), enforce that the organization used to select the verifying `GitHubApp`/secret matches the owner segment of `repository.full_name` (and of `organization.login` when present) before dispatching to handlers — i.e., reject the request (422) if `repository.owner.login`/`organization.login` != `repository.full_name.split('/').first`.

### Proof of Concept
1. Attacker administers GitHub org `attacker-org`, which has a Shipit-connected GitHub App with known `webhook_secret` S.
2. Attacker builds JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S, body)`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: 'attacker-org')`, verifies successfully against `S`. [5](#0-4) 
6. `PushHandler.call(params)` resolves `Repository.from_github_repo_name('victim-org/victim-repo')` and calls `sync_github(expected_head_sha: 'deadbeef')` on the victim's stack, despite the request never being authenticated by `victim-org`'s secret. [3](#0-2) [7](#0-6)

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
