### Title
Webhook signature verification authenticates the wrong field — `repository.owner.login`/`organization.login` is checked, while handlers act on unrelated attacker-controlled fields (`repository.full_name`, raw commit `sha`) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) to verify the HMAC signature against using `repository.owner.login` (or `organization.login`) taken from the untrusted JSON body itself. [1](#0-0) [2](#0-1)  Once the signature check passes, the actual handlers act on a *different* field from the same body that is never re-validated against the field the signature was checked for: `Handler#stacks` resolves the target repository via `payload.dig('repository', 'full_name')`, [3](#0-2)  and `StatusHandler#process` doesn't scope by repository at all — it updates the status of *any* `Commit` in the database matching an attacker-supplied `sha`. [4](#0-3) 

### Finding Description
The equality that should hold is:
`organization whose webhook_secret verified the signature == organization/repository the handler subsequently writes to`

Both sides of this equality are derived from the same attacker-supplied JSON payload, but from *different, independent* keys:
- Left side: `repository.owner.login` / `organization.login`, used only to pick `Shipit.github(organization: repository_owner)` and thus which `webhook_secret` to HMAC-verify against. [5](#0-4) 
- Right side: `repository.full_name` (push/check_suite handlers) or nothing at all (status handler), used to select the `Stack`/`Commit` that is actually mutated. [3](#0-2) 

Shipit explicitly supports hosting multiple independent GitHub Apps/organizations on a single instance, each with its own `webhook_secret` (see `test/dummy/config/secrets_double_github_app.yml` with `OrgOne`/`OrgTwo`, each configuring its own `webhook_secret`). [6](#0-5)  An entity that legitimately administers one onboarded organization ("OrgOne") knows that organization's own `webhook_secret` (they configured the GitHub App for it), which is not considered a privileged/out-of-scope credential relative to a *different* tenant's ("OrgTwo") resources.

An attacker who only knows OrgOne's `webhook_secret` can craft a JSON body where:
- `repository.owner.login` = `"OrgOne"` → `verify_signature` looks up OrgOne's GitHub App and validates the HMAC using the secret the attacker legitimately possesses — passes. [7](#0-6) 
- `repository.full_name` = `"OrgTwo/victim-repo"` → the handler's `stacks`/`Repository.from_github_repo_name` resolves and mutates a Stack that belongs to a completely different, unrelated organization. [8](#0-7) [9](#0-8) 

`StatusHandler` is worse: it performs no repository check whatsoever, and updates the CI status of any `Commit` row in the whole Shipit instance whose `sha` matches the attacker-chosen value (commit SHAs are public, non-secret Git data). [4](#0-3) 

### Impact Explanation
Forged, cross-tenant CI status updates are directly consumable by Shipit's continuous-delivery feature: a stack with `continuous_deployment: true` automatically triggers a deploy once its pending commit becomes "deployable" (its latest CI status is green). [10](#0-9)  Because `StatusHandler` writes a success `Status` for any commit sha in the database regardless of which org's webhook_secret was used to authenticate the request, an attacker who only controls their own organization's GitHub App/webhook_secret can forge a "green" CI status for a target commit belonging to an unrelated victim organization's stack, causing that victim stack's continuous-delivery job to trigger an unauthorized deploy — matching the "unauthorized deploy" Critical impact bar. The push/check_suite handlers similarly allow cross-tenant repository sync/check-run refresh actions on stacks the attacker has no legitimate relationship with, because `repository.full_name` used for the write is never bound to `repository.owner.login`/`organization.login` used for the signature check.

### Likelihood Explanation
This requires only that Shipit be configured to serve more than one GitHub organization (a documented, supported configuration — see `secrets_double_github_app.yml` / `docs/setup.md` multi-org example) [6](#0-5)  and that the attacker legitimately controls one of those organizations (knows its own `webhook_secret`, which they configured themselves and is not a secret belonging to the victim). No access to the victim's credentials, private key, or repository is required — only knowledge of a target commit SHA (public) and the target repository's `full_name` (public). This is a straightforward crafted-HTTP-request attack against the public `/webhooks` endpoint.

### Recommendation
Bind the field used for signature-secret selection to the field used for the actual write:
- After `verify_webhook_signature` succeeds, re-derive the acted-upon repository/organization strictly from the same verified field (`repository.owner.login` and `repository.full_name` must belong to the same owner), and reject the request otherwise.
- In `StatusHandler`, scope the `Commit` lookup by the repository/stack that was cryptographically authenticated (e.g., via the `Repository` resolved from the verified organization), instead of a global, unscoped `Commit.where(sha: params.sha)`.
- More generally, apply the same cross-check in `Handler#stacks` so that `payload.dig('repository','owner','login')` must match the organization whose secret validated the signature before any handler is allowed to mutate a `Stack`/`Commit`.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgOne` and `OrgTwo`, each with its own GitHub App and `webhook_secret` (as in `secrets_double_github_app.yml`).
2. As an administrator of `OrgOne` (who legitimately knows `OrgOne`'s `webhook_secret`), craft a `status` webhook body:
   ```json
   {
     "sha": "<victim commit sha belonging to OrgTwo/victim-repo>",
     "state": "success",
     "context": "ci/forged",
     "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgTwo/victim-repo" }
   }
   ```
3. Sign the raw JSON body with `OrgOne`'s `webhook_secret` and send it to `/webhooks` with header `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgOne")` from `repository.owner.login`, verifies the signature successfully with the attacker-known secret. [1](#0-0) 
5. `StatusHandler#process` updates the status for the victim's commit (matched purely by `sha`, no ownership check), potentially marking it "deployable". [4](#0-3) 
6. If `OrgTwo/victim-repo`'s stack has `continuous_deployment: true`, the next scheduled `Stack.schedule_continuous_delivery` run finds the now-"deployable" commit and enqueues an unauthorized deploy for a repository/organization the attacker never had access to. [10](#0-9)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/stack.rb (L129-133)
```ruby
    def self.schedule_continuous_delivery
      not_archived.where(continuous_deployment: true).find_each do |stack|
        ContinuousDeliveryJob.perform_later(stack)
      end
    end
```
