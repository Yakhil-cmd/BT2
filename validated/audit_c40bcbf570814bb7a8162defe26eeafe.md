### Title
Webhook signature is verified against an attacker-chosen organization while `StatusHandler` writes commit statuses globally by SHA, allowing CI status forgery on any repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to verify the HMAC signature against using a field taken from the *unverified* JSON body, before the signature itself has been validated. `Shipit::Webhooks::Handlers::StatusHandler`, however, applies the resulting `status` event to any `Commit` row across the entire installation that matches the payload's `sha`, with no check that the commit belongs to the organization/repository whose secret authenticated the request. This breaks the binding "organization authenticated == repository written," letting an unprivileged attacker forge a commit status for a stack belonging to a completely different, better-protected organization.

### Finding Description
`repository_owner`, used to pick the webhook signing secret, is derived straight from the raw, not-yet-verified request body: [1](#0-0) 

That value feeds directly into secret selection before the signature check occurs: [2](#0-1) 

`verify_webhook_signature` only verifies the HMAC using whichever organization's `webhook_secret` was resolved, and explicitly treats a *missing* secret as automatically verified: [3](#0-2) 

Shipit's own documentation confirms multi-organization installs are supported, and that `webhook_secret` is optional per organization ("If you've set a webhook secret ... you should copy it here"): [4](#0-3) [5](#0-4) 

Once the signature is accepted, `StatusHandler#process` applies the event to any commit anywhere in the database that shares the given `sha`, with no scoping to the repository/organization that was actually authenticated: [6](#0-5) 

Contrast this with the base `Handler` class, which does have repository-scoping helpers (`stacks`/`repository_name` from `repository.full_name`) that other handlers (`PushHandler`, PR handlers, etc.) use, but `StatusHandler` bypasses that scoping entirely and only filters by `sha`: [7](#0-6) [8](#0-7) 

The equality that should hold is: `organization whose secret authenticated the request == organization/repository the commit-status write is applied to`. Because `repository_owner` is read from the attacker-controlled body prior to verification, and the eventual write only keys off `sha` (a 40-character hex value that is often disclosed publicly, e.g. in GitHub URLs, CI logs, PR pages, or the Shipit UI itself), an attacker who only controls (or knows the secret of, including "no secret configured") one organization on a shared multi-org Shipit instance can forge a `status` webhook naming that organization as `repository.owner.login`/`organization.login`, pass signature verification, but include an arbitrary `sha` belonging to a commit tracked under a completely different, unrelated, better-secured organization's stack.

### Impact Explanation
Commit statuses recorded via `create_status_from_github!` feed Shipit's deploy-safety gating (blocking statuses / deployable commit checks). By forging a passing status (e.g. `state: "success"`) for a targeted commit in a victim stack that the attacker does not control and whose organization's real webhook secret they never obtained, the attacker can make an otherwise CI-blocked or unchecked commit appear deployable, enabling an unauthorized deploy of code that never actually passed the required checks. This falls under "unauthorized deploy" in the Critical impact bucket. The severity is compounded by the fact that a single Shipit installation commonly manages multiple organizations/repositories with differing security posture, and per the documented configuration, some of those organizations may have no `webhook_secret` configured at all, making the initial authentication step trivially satisfiable for the attacker's own org while still touching a foreign one.

### Likelihood Explanation
Exploitation requires only: (1) the target Shipit instance manages more than one GitHub organization (an explicitly documented, supported configuration) or has any organization configured without a `webhook_secret`; (2) the attacker knows or can trigger a commit SHA in the victim stack — trivial, since SHAs are not secret (visible in the GitHub UI, PR pages, CI links, or the Shipit UI itself); (3) the attacker can send an HTTP POST to the shared `/github/webhooks` endpoint with a body they fully control and a correctly-signed (or unsigned-because-absent-secret) `X-Hub-Signature`. No repository write access, session, or `ApiClient` token is required — only network access to the public webhook endpoint, which is unauthenticated by design (webhook verification is the *only* gate). This makes the likelihood high wherever multi-org or no-secret configurations are in use.

### Recommendation
Move signature verification to a per-organization/per-repository binding that cannot be spoofed by the payload contents used later for processing: verify the signature using the secret associated with the *stack*/repository the event ultimately targets (e.g., resolve via `repository.full_name`, not `repository.owner.login`/`organization.login` alone), and require `StatusHandler` (and any other handler that doesn't already scope by `repository.full_name`) to restrict writes to commits belonging to stacks whose repository matches the authenticated organization. Do not treat an absent `webhook_secret` as "auto-verified" when any other configured organization in the same installation has a secret set; either require all organizations to configure secrets or fail closed for cross-organization ambiguity.

### Proof of Concept
1. Shipit is configured with two GitHub organizations in `secrets.yml`: `attacker-org` (no `webhook_secret` configured) and `victim-org` (real, secret-protected repositories/stacks).
2. Attacker learns the SHA of a commit under a `victim-org` stack (e.g., from a public PR link or the Shipit UI) that is not yet marked deployable due to a pending/blocking CI status.
3. Attacker sends:
   ```
   POST /github/webhooks
   X-Github-Event: status
   X-Hub-Signature: sha1=<any value, or omitted — verification returns true since attacker-org has no webhook_secret>
   {
     "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/whatever"},
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/blocking-check"
   }
   ```
4. `WebhooksController#verify_signature` resolves `repository_owner` as `attacker-org`, calls `Shipit.github(organization: "attacker-org")`, and `verify_webhook_signature` returns `true` unconditionally (no secret configured).
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit (regardless of organization), and calls `commit.create_status_from_github!(params)`, recording a forged "success" status for `ci/blocking-check` on the victim's commit — potentially satisfying Shipit's deploy-blocking-status requirement and allowing an unauthorized deploy to proceed.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
