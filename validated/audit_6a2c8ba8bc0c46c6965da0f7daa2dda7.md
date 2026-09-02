## Root cause

`WebhooksController#verify_signature` decides which GitHub App/organization secret to validate the inbound webhook's `X-Hub-Signature` against by reading a field out of the very payload it is about to validate: [1](#0-0) [2](#0-1) 

Once the signature check passes, the actual event-processing handlers determine the target `Stack`/`Repository` using a **different** field from the same JSON body — `repository.full_name` — with no cross-check against the field used to pick the verification secret: [3](#0-2) 

In Shipit's documented multi-tenant configuration ("Using Multiple Github Applications"), each organization has its own distinct `webhook_secret`: [4](#0-3) 

The binding that should hold is:
`organization whose secret authenticated the request == organization that owns the repository the handlers act on`

But the engine only enforces:
`params.dig('repository','owner','login')` (or `organization.login`) selects the HMAC secret, while `params.dig('repository','full_name')` selects the `Stack`/`Repository` acted upon — two independent, attacker-writable fields inside a body an attacker can fully control as long as they know *any one* configured org's secret.

## Attack

An attacker who legitimately possesses the webhook secret for **OrgA** (one tenant on a shared Shipit instance) can POST directly to `/webhooks` (this is a plain HTTP endpoint, not restricted to GitHub's IPs) a forged JSON body where:
- `repository.owner.login` = `"OrgA"` (or `organization.login` = `"OrgA"`) → `verify_signature` looks up `Shipit.github(organization: "OrgA")` and validates against OrgA's secret, which the attacker computes correctly.
- `repository.full_name` = `"OrgB/victim-repo"` → the dispatched handler resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")`, i.e. a completely different tenant's stack.

Concretely, using the `status` event and `StatusHandler`: [5](#0-4) 

the attacker can create an arbitrary `CommitStatus` (state `success`, arbitrary `context`) on a commit that belongs to a repository/stack they do not own and have no legitimate GitHub webhook access to. Since Shipit's merge-queue and continuous-delivery gating rely on GitHub commit statuses (`ci.require`, `merge.require` in `shipit.yml`), forging a passing status can unblock/trigger an unauthorized merge or deploy on a victim tenant's stack. The `push` handler is similarly exploitable to trigger `sync_github` for the victim stack using an attacker-chosen SHA.

## Rules compliance

This fits the required class exactly: "an organization that authenticated versus the repository that is written" — the org whose secret validated the signature is not cryptographically tied to the repository/stack that the handlers subsequently mutate. It requires no privileged Shipit session, `ApiClient` token, GitHub App private key, or repository write access on the victim's side — only knowledge of a *different*, unrelated tenant's `webhook_secret`, which is exactly the credential this endpoint is designed to check.

### Title
Webhook signature verification keys off an unbound `repository.owner`/`organization` field, allowing cross-organization webhook forgery in multi-tenant deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App secret used to validate `X-Hub-Signature` from `params.dig('repository','owner','login')` (or `organization.login`), a field taken from the attacker-supplied JSON body itself. Downstream handlers, however, resolve the target `Stack`/`Repository` from a separate field, `repository.full_name` (`Handler#repository_name`). These two fields are never cross-validated, so possession of any one tenant's webhook secret is sufficient to forge signed events that target a completely different tenant's stack.

### Finding Description
- `verify_signature` computes `repository_owner` from the unverified JSON body and uses it to pick which org's `webhook_secret` to check the HMAC against: `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`.
- All event handlers inherit from `Handler`, which independently derives the acted-upon repository from `payload.dig('repository', 'full_name')`: `app/models/shipit/webhooks/handlers/handler.rb:32-38`.
- Nothing ties the `repository.owner.login`/`organization.login` used for authentication to the `repository.full_name` used for authorization/action. An attacker who knows OrgA's `webhook_secret` (a value scoped, per the docs, to a single organization/tenant in a shared install: `docs/setup.md:182-209`) can freely set `repository.full_name` to any other tenant's repo while keeping `repository.owner.login` = `"OrgA"` to pass the signature check with the key they control.

### Impact Explanation
This is a cross-repository/cross-tenant write: the forged webhook can create arbitrary `CommitStatus` records for another tenant's commits via `StatusHandler` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), or trigger `PushHandler`-driven syncs on another tenant's stack (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`). Forged "success" CI statuses can defeat `ci.require`/`merge.require` gating and enable an unauthorized merge or deploy on a stack the attacker has no legitimate access to — matching the Critical impact category "cross-repository writes, or an unauthorized deploy, rollback or merge."

### Likelihood Explanation
Requires only knowledge of a webhook secret for *any* one organization configured on a shared/multi-tenant Shipit instance (a scenario explicitly documented and supported by the engine) plus the ability to send an arbitrary HTTP POST to the public `/webhooks` endpoint — no GitHub-side access, no Shipit session, and no privileges on the victim organization are needed.

### Recommendation
Bind the field used for signature-secret selection to the field used for authorization: derive both the verification organization and the acted-upon repository from a single, consistently-scoped value (e.g., always require `repository.full_name`'s owner segment to match the org used for `verify_webhook_signature`, and reject if `repository.owner.login`/`organization.login` disagree with the owner segment of `repository.full_name`).

### Proof of Concept
1. Configure Shipit with two tenants, `OrgA` and `OrgB`, each with distinct `webhook_secret`s (per `docs/setup.md`'s multi-app section).
2. As an attacker who only knows `OrgA`'s `webhook_secret`, build a `status` event JSON body:
```json
{
  "sha": "<victim_commit_sha_in_OrgB_repo>",
  "state": "success",
  "context": "continuous-integration/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac_sha1(OrgA_webhook_secret, body)>` and POST to `/webhooks` with header `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches OrgA's `GitHubApp`, and the HMAC validates successfully (`app/controllers/shipit/webhooks_controller.rb`).
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` for the victim SHA in `OrgB/victim-repo` and calls `create_status_from_github!`, creating a forged passing status on a repository the attacker never authenticated against.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
