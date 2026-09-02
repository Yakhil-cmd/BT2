This confirms the full exploit chain. I have enough to write the finding now.

### Title
Webhook signature verification keyed on `repository.owner.login` while write target keyed on `repository.full_name`, enabling unsigned commit-status forgery that triggers unauthorized deploys - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate a webhook's HMAC signature against using `repository.owner.login` (or `organization.login`) from the untrusted JSON body itself. But the handler that actually decides which `Stack`/`Repository` gets mutated (`Shipit::Webhooks::Handlers::Handler#repository_name`) reads a *different* field from that same body: `repository.full_name`. These two attacker-controlled fields are never required to be consistent, and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when the selected organization has no `webhook_secret` configured — a state explicitly documented as the default/optional configuration in this engine's own setup docs.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) 

selects the app/secret via `repository_owner`: [2](#0-1) 

and `GitHubApp#verify_webhook_signature` bypasses verification entirely when that org has no secret: [3](#0-2) 

Meanwhile, event handlers (e.g. `StatusHandler`) resolve the actual write target from `repository.full_name`, an entirely separate JSON key not used in the signature-org lookup: [4](#0-3) [5](#0-4) 

Because `repository_owner` and `repository.full_name` are independent, attacker-controlled fields in the same forged JSON body, an attacker who knows (or is deployed into) a Shipit install where **any one** configured GitHub organization has no `webhook_secret` (the setup docs and every provided secrets template ship this as `# nil`/optional) can craft a POST to `/webhooks` with:
- `repository.owner.login` (or `organization.login`) = the org with no secret → `verify_signature` calls `Shipit.github(organization: that_org).verify_webhook_signature` which returns `true` unconditionally, regardless of the `X-Hub-Signature` header.
- `repository.full_name` = any other tracked repository (belonging to any other, properly-secured organization) that Shipit tracks as a `Stack`.

This forged, unsigned request is then routed by event handlers using `repository.full_name`, letting the attacker act on a repository/organization they have no relationship with and for which they never produced a valid signature.

The `status` event handler is the most impactful: `Commit#create_status_from_github!` creates a `Status` record from attacker-controlled `state`/`context`/`description`, which feeds `Commit#deployable?` and `Commit#schedule_continuous_delivery`: [6](#0-5) [7](#0-6) 

If continuous deployment is enabled on the targeted stack, a forged `success` status can make `stack.deployable?`/`commit.deployable?` true and cause `ContinuousDeliveryJob`/`trigger_continuous_delivery` to fire, resulting in an unauthorized deploy of that stack.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary defined for this engine: signature validation authenticates against Org A's (or an unsecured org's) identity, while the mutation is applied to a completely different Org B/repository's `Stack`. The concrete outcome — forging a passing CI `status` for a commit and thereby triggering `Stack#trigger_continuous_delivery` — is an **unauthorized deploy**, which falls in the Critical impact bucket. No GitHub credentials, Shipit session, or `ApiClient` token are required; the attacker only needs network access to the `/webhooks` endpoint and knowledge that the instance has at least one org configured without `webhook_secret` (a state the project's own setup docs and templates present as the default/optional condition).

### Likelihood Explanation
Requires a multi-organization Shipit deployment (documented and supported: "Using Multiple Github Applications") where at least one configured org has no `webhook_secret` set — explicitly shown as `# nil` (optional) in every shipped secrets template (`config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, `docs/setup.md`). Given webhook secrets are documented as optional, and organizations are commonly added incrementally, this is a plausible real-world configuration, not a contrived edge case.

### Recommendation
- Derive the signature-verification organization from the same trusted value used for routing (`repository.full_name`'s owner segment), and reject requests where `repository.owner.login`/`organization.login` disagree with `repository.full_name`'s owner.
- Do not allow `verify_webhook_signature` to silently return `true` for a organization different than the one the payload claims to write to; if a global bypass for "no secret configured" is desired, scope it strictly per-repository/per-stack rather than per attacker-chosen org key.
- Consider requiring `webhook_secret` to be present for every configured organization, or refusing to process webhooks referencing repositories outside the authenticated organization.

### Proof of Concept
Assume `secrets.yml` configures two orgs: `trusted-org` (has `webhook_secret` set) and `open-org` (no `webhook_secret`, e.g. left as `# nil` per the shipped templates), and Shipit tracks a stack for `trusted-org/victim-repo` with continuous deployment enabled.

```
POST /webhooks HTTP/1.1
X-Github-Event: status
Content-Type: application/json
# No valid X-Hub-Signature needed

{
  "sha": "<head sha of trusted-org/victim-repo>",
  "state": "success",
  "context": "ci/forged",
  "repository": {
    "owner": { "login": "open-org" },
    "full_name": "trusted-org/victim-repo"
  }
}
```

- `verify_signature` calls `Shipit.github(organization: "open-org")` (from `repository.owner.login`) → `verify_webhook_signature` returns `true` because `open-org` has no `webhook_secret` (`app/controllers/shipit/webhooks_controller.rb` line 25; `lib/shipit/github_app.rb` line 77).
- `StatusHandler#process` runs unauthenticated and resolves the target via `payload.dig('repository', 'full_name')` = `"trusted-org/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb` lines 36-38), creating a forged `success` `Status` on `trusted-org`'s tracked commit.
- If `trusted-org/victim-repo`'s stack has continuous deployment enabled, `Commit#schedule_continuous_delivery` → `Stack#trigger_continuous_delivery` fires an unauthorized deploy.

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

**File:** app/models/shipit/commit.rb (L227-230)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
