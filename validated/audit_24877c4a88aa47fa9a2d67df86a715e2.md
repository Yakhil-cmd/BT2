### Title
Webhook signature verification is bound to the organization named in the payload, not the repository the handlers act on, allowing cross-repository status/event forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC signature with by reading `repository.owner.login` out of the **same untrusted JSON body** it is about to verify. The handlers that actually act on the payload (`PushHandler`, `CheckSuiteHandler`, and especially `StatusHandler`) resolve the target repository/commit from a *different* field of that same body (`repository.full_name`, or for `StatusHandler`, no repository field at all — just a global `sha` lookup). Because the field used to pick the verification secret and the field(s) used to decide what gets mutated are never cross-checked against each other, an attacker who controls any one organization/repository onboarded into this Shipit instance can forge a signature that validates against their own org's secret while making the handler operate on a completely different, victim repository/stack.

### Finding Description
`verify_signature` picks the verifying GitHub App config purely from payload content: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization: repository_owner)` returns the `GithubApp`/`GithubOrganization` config (and thus the `webhook_secret`) for whichever organization name appears in the payload, then verifies the raw body's HMAC against *that* secret. The intended invariant is:

```
verified_org(signature) == owning_org(repository_acted_on)
```

But the base `Handler` class resolves the repository to act on from an entirely separate field, never reconciled with `repository_owner`: [3](#0-2) 

`PushHandler` and `CheckSuiteHandler` use `stacks` (i.e., `Repository.from_github_repo_name(payload['repository']['full_name'])`) to select which stacks to sync/refresh: [4](#0-3) [5](#0-4) 

`StatusHandler` is worse — it performs **no repository scoping whatsoever**, matching purely on commit SHA across the entire instance: [6](#0-5) 

Since `owning_org(repository_acted_on)` is never checked to equal `verified_org(signature)`, an attacker who operates their own repository/organization already registered with this Shipit instance (each org can have a distinct `webhook_secret` per `lib/shipit/github_app.rb`'s `verify_webhook_signature`) can:

1. Craft a JSON body with `repository.owner.login` = their own org (so `verify_signature` picks their own org's secret) and sign it correctly with that secret.
2. Set the `repository.full_name` field (for push/check_suite) or simply the `sha` field (for status, no repository field is even consulted) to reference a victim repository/commit they do not control.
3. POST it to `WebhooksController#create`; signature verification passes because it only checks the payload against the secret selected from the attacker-controlled field, and the handler then mutates state belonging to the victim's stack/commit.

This is exactly the "hooks may break invariants" bug class from the report, translated into this codebase: the field that is authenticated (`repository.owner.login`, used to select the signing secret) is not the same field that is acted upon (`repository.full_name` / bare `sha`), so the security guarantee "the signature proves the organization owning the affected repository sent this" does not hold.

### Impact Explanation
The most severe concrete path is through `StatusHandler`: forging a GitHub `status` event lets an attacker mark an arbitrary commit (identified only by its public SHA) as `success` in Shipit, via `Commit#create_status_from_github!`. Shipit stacks gate deployability/continuous-deployment decisions on commit status state (`deployable?`, release status checks in `app/models/shipit/deploy.rb` / `app/models/shipit/release_status.rb`). Forging a passing status for a victim's commit can cause an otherwise-blocked or CI-failing commit to appear deployable, enabling an **unauthorized deploy** of unverified code, or falsely satisfying merge/CD gating (`schedule_continuous_delivery`, `trigger_deploy`). `PushHandler`/`CheckSuiteHandler` similarly let an attacker trigger `GithubSyncJob` or check-run refreshes against a victim's stack it does not own, causing state confusion. This matches the "unauthorized deploy or rollback" High/Critical impact class.

### Likelihood Explanation
Exploitability requires only that the attacker controls (or has webhook-signing capability for) *one* organization/repository already onboarded into the target Shipit instance — no access to the victim organization, victim GitHub App, or victim `webhook_secret` is needed. Multi-tenant Shipit deployments serving several GitHub organizations are the intended and documented use case (`Shipit.github(organization:)`, `GithubOrganizationUnknown`), making the precondition realistic wherever more than one organization/secret is configured. The victim commit SHA is public information obtainable from GitHub, so no secret knowledge of the victim is required for the `status` variant.

### Recommendation
Bind webhook signature verification and payload dispatch to the same, single source of truth for "which repository/organization does this event concern":
- Have `verify_signature` record which organization's secret actually validated the payload, then require every handler to verify that `payload['repository']['full_name']` (or the commit's owning repository, for `StatusHandler`) belongs to that same verified organization before mutating anything.
- Reject events whose `repository.owner.login`/`organization.login` does not match the GitHub organization that owns the repository/stack being acted upon.
- For `StatusHandler`, scope the `Commit.where(sha: params.sha)` lookup to commits whose stack's repository belongs to the verified organization, instead of a global unscoped lookup.

### Proof of Concept
1. Onboard/attacker-control organization `evil-org` in the target Shipit instance (has its own `webhook_secret`, e.g., via a GitHub App installation or a repository they legitimately manage).
2. Obtain the public SHA of a commit in victim stack `victim-org/victim-repo` that Shipit is tracking (visible via GitHub UI/API).
3. Build a GitHub `status` webhook payload:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "evil-org" }, "full_name": "evil-org/evil-repo" }
}
```
4. Sign the raw body with `evil-org`'s `webhook_secret` (`sha1=` HMAC per `lib/shipit/github_app.rb#verify_webhook_signature`) and send it to `POST /webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner` = `evil-org`, loads `evil-org`'s config, and the signature validates. `StatusHandler#process` then runs `Commit.where(sha: params.sha)`, finds the victim's commit (unscoped by repository), and creates a `success` status on it — despite the attacker having no relationship to `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
