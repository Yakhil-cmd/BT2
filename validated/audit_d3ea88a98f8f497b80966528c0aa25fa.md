### Title
Webhook signature verification is scoped to `repository.owner.login`/`organization.login` while the event's effect (repository resolution and commit-status writes) is scoped to unrelated, unauthenticated payload fields - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which `GithubApp` (and thus which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (or `organization.login` as a fallback). The rest of the pipeline, however, determines *what gets written* using completely different, unauthenticated fields: `Handler#repository_name` reads `payload.dig('repository', 'full_name')` to resolve the target `Stack`, and `StatusHandler#process` queries `Commit.where(sha: params.sha)` with no repository/organization scoping at all. Nothing binds "the organization whose secret validated this signature" to "the repository/commit this event is applied to."

### Finding Description
- Signature check: `verify_signature` picks the signing organization solely from the payload itself (`repository_owner`), then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
- `GithubApp#verify_webhook_signature` explicitly no-ops when that organization's `webhook_secret` is blank: `return true unless webhook_secret`. [3](#0-2) 
- This is a supported, documented configuration — Shipit ships fixtures/config for multiple simultaneous GitHub App configs per install (`test/dummy/config/secrets_double_github_app.yml`) and per-hook code elsewhere in the same model family explicitly supports "no secret configured" as a valid state (`Hook#deliver!`/`DeliverySpec#signature` returns `nil` when `secret.blank?`). [4](#0-3) 
- Once the request passes (or is exempted from) signature verification, the actual repository being mutated is picked from a *different* JSON field, `repository.full_name`, with no cross-check against `repository.owner.login` used above: [5](#0-4) 
- Worse, `StatusHandler` doesn't even use repository scoping — it looks up commits globally by `sha` across the entire Shipit database and writes a `CommitStatus` to whatever `Commit` matches: [6](#0-5) 

The security invariant that should hold is: `organization that authenticated the payload == organization owning the repository/commit that is written`. That equality is never enforced. An attacker who controls (or who targets) any organization configured in the Shipit instance without a `webhook_secret` (or with a leaked/guessable one for a low-value org) can pass `verify_signature` trivially, then supply `repository.full_name` and/or `sha` values pointing at a completely different, unrelated stack/commit that they do not control.

### Impact Explanation
This breaks a repository/organization trust boundary that the webhook signature is meant to enforce. Concretely, an attacker who satisfies signature verification for one (weakly-configured) organization can:
- Forge GitHub commit statuses (`Commit#create_status_from_github!`) for commits belonging to any stack in the installation, since `StatusHandler` performs no ownership check between the authenticating org and the target commit.
- Enqueue `GithubSyncJob`/`RefreshCheckRunsJob` for arbitrary stacks resolved purely from `repository.full_name`, which is attacker-supplied and never checked against the verified organization.

Because Shipit gates deploy eligibility on commit/check statuses (`deployable_status`, CI checks), forging a passing status on a targeted commit can be used to make an otherwise-non-deployable commit appear deployable, contributing to an unauthorized deploy — matching the Critical impact bar of "unauthorized deploy" in this program's rules.

### Likelihood Explanation
Requires only: (a) the Shipit instance configuring more than one GitHub App/organization (a documented, supported setup — see `test/dummy/config/secrets_double_github_app.yml`), and (b) at least one configured organization with no `webhook_secret` set (an explicitly supported code path, `return true unless webhook_secret`) or with a secret known to a lower-trust party. Given both, no privileged credential, session, or repository access is needed — this is a fully unauthenticated network attacker hitting `/github/webhooks`. Sha guessing for `StatusHandler` is aided by the fact that git commit SHAs are public identifiers routinely visible via GitHub UI/API for any repo the attacker can view, including public repos mirrored/tracked by the same Shipit instance.

### Recommendation
Bind the verified signing organization to the entity being mutated:
- In `WebhooksController`, after `verify_signature` succeeds, assert `repository_owner` matches the owner encoded in `repository.full_name` (and reject if they differ).
- In `Webhooks::Handlers::Handler`/`StatusHandler`, scope commit/status lookups to the repository resolved from the same trusted, verified organization rather than performing a global `Commit.where(sha:)` lookup, e.g., by joining through `stacks`/`Repository` filtered by the authenticated owner.

### Proof of Concept
1. Shipit is configured with two GitHub Apps/organizations, e.g. `attacker-org` (no `webhook_secret` configured) and `victim-org` (secret unknown to attacker) — see supported multi-app config shape in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker POSTs to `/github/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<known victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. `verify_signature` calls `Shipit.github(organization: "attacker-org").verify_webhook_signature(...)`, which returns `true` immediately because `attacker-org` has no `webhook_secret` (`lib/shipit/github_app.rb:76-83`), regardless of the actual signature header sent (or with none at all).
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a forged `CommitStatus` on the victim's commit — despite the request never being signed by `victim-org`'s secret.

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

**File:** app/models/shipit/hook.rb (L54-58)
```ruby
      def signature
        return nil if secret.blank?

        DeliverySigner.new(secret).sign(payload)
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
