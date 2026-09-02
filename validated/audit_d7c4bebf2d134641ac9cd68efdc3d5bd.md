### Title
Webhook signature is verified against the payload's `repository.owner.login`, but handlers act on `repository.full_name` and unscoped commit SHAs, letting one onboarded organization forge status/push events for another organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
Shipit supports multiple GitHub Apps/organizations configured on a single instance (`Shipit.github(organization:)`). The webhook signature check picks the HMAC secret to verify against based on a field taken from the untrusted, attacker-supplied JSON body (`repository.owner.login`), but the event handlers that subsequently act on the payload key off a *different*, equally attacker-controlled field (`repository.full_name`) — or, in the `status` handler, off no repository binding at all. This breaks the intended binding "organization whose secret authenticated the request == repository/stack being written to."

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/organization used to validate the HMAC signature purely from the JSON body itself: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login')` — fully controlled by the request body, before any authentication has taken place. Once `verify_webhook_signature` succeeds (using *that org's* `webhook_secret`), the raw params are dispatched to handlers unmodified: [3](#0-2) 

The base `Handler` class, used by `PushHandler`, `PullRequest::*`, and `CheckSuiteHandler`, resolves the target `Stack`/`Repository` from a *different* field in the same attacker-controlled body — `repository.full_name` — with no cross-check that this repository actually belongs to the organization that produced a valid signature: [4](#0-3) 

`StatusHandler` is even less scoped: it looks up commits purely by SHA across the *entire* multi-tenant database, with no repository/organization filter at all: [5](#0-4) 

So the equality that should hold is:
`organization whose webhook_secret verified the HMAC == organization owning the repository/stack acted upon`

but the actual code enforces:
`organization whose webhook_secret verified the HMAC == organization named in an unverified field of the same forgeable body`

An attacker who legitimately controls one organization onboarded to a shared Shipit instance (and therefore possesses/derives a valid signature using their own org's `webhook_secret`, or replays a real webhook delivery from their own repo) can set `repository.owner.login` to their own org (so the signature check passes) while setting `repository.full_name` to a victim organization's repository name, or simply guess/observe a victim commit `sha` for the `status` event. This lets them:
- Inject fabricated commit statuses (`commit.create_status_from_github!`) for any commit belonging to any other tenant's stack via `StatusHandler`, since lookup is by `sha` only, not scoped to the authenticating org/repository.
- Force `PushHandler`/`sync_github` calls against another organization's stacks by spoofing `repository.full_name`.

### Impact Explanation
Forged commit statuses can flip a commit's CI/deployable state as tracked by Shipit for a stack the attacker does not own or control on GitHub. Depending on stack configuration (`required_checks`, deploy/merge-queue gating on commit status), this can make a commit appear deployable/mergeable when it is not, enabling an unauthorized deploy or merge decision to be made by Shipit's own automation for a repository the attacker has no legitimate write access to — this crosses the "unauthorized deploy/merge" impact bar. It is a cross-tenant/cross-repository authorization boundary break stemming purely from confusing which payload field is authenticated versus which field drives the write.

### Likelihood Explanation
Requires the attacker to be an "unprivileged" outsider only in the sense of having no access to the *victim* organization/repo, while operating as a legitimate (even if low-trust) tenant with their own organization/app/webhook secret configured on the same shared Shipit instance (a supported, documented multi-org configuration, per `test/dummy/config/secrets_double_github_app.yml`-style setups and `Shipit.github(organization:)`). No knowledge of the victim's secret, GitHub token, or repository access is required — only the ability to send a signed webhook to the shared Shipit instance with a spoofed `repository` field or a known commit SHA.

### Recommendation
Bind the verified signer to the object being written: after computing `repository_owner` and verifying the signature, re-derive and hard-require that `repository.full_name`'s owner matches the verified `repository_owner`, and reject (422) on mismatch, before dispatching to handlers. Additionally, scope `StatusHandler`'s `Commit.where(sha: params.sha)` lookup by the repository/stack derived from the same verified organization (e.g., join through `Repository`/`Stack` matching `repository_owner`), rather than a global, repository-agnostic SHA lookup.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret` (a supported configuration, see `config/secrets_double_github_app.yml`-style setup and `Shipit.github(organization:)`).
2. As the operator of `attacker-org`, compute a valid `X-Hub-Signature` over a JSON body using `attacker-org`'s `webhook_secret`, where the body is:
```json
{
  "sha": "<victim-org commit sha, e.g. from a public repo>",
  "state": "success",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
}
```
3. POST to `/github/webhooks` with `X-Github-Event: status` and the computed signature.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org`, verifies successfully with `attacker-org`'s secret.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — unscoped by repository — creating a forged `success` status on the victim's commit, independent of `attacker-org` having any relationship to that commit/repository. [5](#0-4)

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
