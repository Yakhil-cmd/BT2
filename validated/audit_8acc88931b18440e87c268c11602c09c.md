### Title
Webhook signature verification authenticates against the payload's `repository.owner.login`/`organization.login`, but handlers act on data identified by unrelated fields (`repository.full_name`, or bare commit `sha` with no repository scope at all) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to use for HMAC verification based on `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). [1](#0-0)  That verification result is then used to accept the *entire* raw payload, which is dispatched to handlers that identify what to act on using **different, unrelated fields**: `PushHandler`/`CheckSuiteHandler` key off `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name`, [2](#0-1)  and `StatusHandler` doesn't scope by repository/organization at all - it matches purely on commit `sha` across the entire installation. [3](#0-2) 

Because `verify_webhook_signature` short-circuits to `true` whenever the selected organization has no `webhook_secret` configured (a documented, valid configuration state), [4](#0-3)  any organization onboarded to a multi-tenant Shipit instance without a webhook secret becomes a skeleton key: an attacker can pick that org's login for `repository.owner.login`/`organization.login` (satisfying the authentication check) while pointing the actual payload data (`repository.full_name`, commit `sha`) at a completely unrelated, properly-secured victim repository.

### Finding Description
The binding that should hold is:

`organization whose webhook_secret authenticated the request == organization/repository that the dispatched handler mutates`

Before the exploit, this equality is implicit and assumed to hold because in a genuine GitHub-originated webhook, `repository.owner.login` and `repository.full_name`'s owner prefix are always the same and both are produced by GitHub, not the client. After the exploit, the equality is broken: `verify_signature` derives its trust decision solely from `repository_owner`, [5](#0-4)  while `create` blindly forwards the entire parsed JSON body to every registered handler for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [6](#0-5)  Nothing re-validates that the fields consumed downstream (`repository.full_name` in `Handler#repository_name`, or the bare `sha` in `StatusHandler`) belong to the organization that was actually authenticated.

Combined with `GitHubApp#verify_webhook_signature`'s `return true unless webhook_secret` fallback, [4](#0-3)  and the fact that `webhook_secret` is explicitly documented/scaffolded as an optional, nil-able field per-organization (`webhook_secret: # nil`), [7](#0-6)  an attacker only needs to know the login of *any* configured organization on the instance that happens to have no webhook secret set. They do not need write access to any repository, an API token, or any Shipit session/`ApiClient` — the `/webhooks` endpoint is unauthenticated by design and only relies on signature verification.

### Impact Explanation
- `StatusHandler` writes CI status onto any `Commit` matching an attacker-chosen `sha`, with zero repository/organization scoping. [3](#0-2)  An attacker can forge a `success` status for a real commit belonging to any stack in the instance. If that stack has continuous deployment/merge-queue enabled and depends on required CI contexts (`ci.require` in `shipit.yml`), this can unblock/trigger an **unauthorized deploy**.
- `PushHandler` and `CheckSuiteHandler` resolve the target `Stack` via `payload.dig('repository', 'full_name')`, [2](#0-1)  letting the attacker force a resync (`stack.sync_github`) or check-run refresh against any repository configured in the instance while having "authenticated" as an unrelated, secret-less organization.
- This satisfies the Critical bucket criterion of "an unauthorized deploy" by breaking the authenticated-organization ↔ acted-upon-repository binding.

### Likelihood Explanation
Requires: (a) a multi-tenant Shipit deployment with at least two organizations configured, and (b) at least one of those organizations having no `webhook_secret` set — a state explicitly supported and scaffolded by the codebase's own templates/config examples. [8](#0-7)  Organization logins are generally public/discoverable on GitHub, so the main precondition is operational (an org onboarded without a secret), not cryptographic. No credentials, tokens, or sessions are needed by the attacker.

### Recommendation
- After signature verification, re-derive the organization/repository from the *same* verified source used to select the `webhook_secret`, and reject (or re-verify) the payload if `payload.dig('repository','full_name')`'s owner does not match `repository_owner`.
- In `StatusHandler`, scope the `Commit` lookup by the verified repository/stack, not just by bare `sha`.
- Consider making `webhook_secret` mandatory for all configured organizations (fail closed) rather than allowing silent bypass when absent.

### Proof of Concept
1. Configure Shipit with two organizations: `org-no-secret` (no `webhook_secret`) and `victim-org` (properly secured, hosts a stack tracked by Shipit with CI-gated continuous deployment).
2. POST to `/webhooks` with:
   - `X-Github-Event: status`
   - `X-Hub-Signature: sha1=anything`
   - Body:
     ```json
     {
       "organization": { "login": "org-no-secret" },
       "sha": "<victim commit sha awaiting CI>",
       "state": "success",
       "context": "ci/required-check"
     }
     ```
3. `verify_signature` resolves `Shipit.github(organization: "org-no-secret")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the bogus signature. [4](#0-3) 
4. `StatusHandler#process` finds `Commit.where(sha: params.sha)` — matching the victim's commit despite it belonging to `victim-org`, not `org-no-secret` — and records a forged `success` status. [3](#0-2) 
5. If `victim-org`'s stack has continuous deployment configured to deploy once all required statuses are green, this forged status can trigger an unauthorized deploy.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
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

**File:** config/secrets.development.shopify.yml (L5-18)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
```
