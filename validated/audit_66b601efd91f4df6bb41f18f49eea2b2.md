### Title
Webhook signature verification authenticates a different organization than the repository/commit the handlers act on - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC `webhook_secret`) to validate a webhook against using the organization extracted from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`). Every subsequent handler, however, resolves the repository/stack/commit to act on from other, independently-controlled fields of the same JSON body — `payload.dig('repository', 'full_name')` for push/pull_request handlers, or an unscoped `sha` lookup with no repository filter at all for the `status` event. Nothing ties the authenticated organization back to the entity that is ultimately mutated.

### Finding Description
`verify_signature` computes trust like this: [1](#0-0) [1](#0-0) [2](#0-1) 

It fetches `Shipit.github(organization: repository_owner)` and verifies the raw body against that organization's own `webhook_secret` via `GitHubApp#verify_webhook_signature`: [3](#0-2) 

Once the signature check passes (which only proves the request was signed with the secret belonging to `repository_owner`, e.g. `payload['repository']['owner']['login']`), the full parsed body is dispatched unchanged to handlers: [4](#0-3) 

Handlers derive the repository to act on from a *different* field, `repository.full_name`, with no cross-check that its owner matches the organization that authenticated the request: [5](#0-4) [6](#0-5) 

`PushHandler` uses this unchecked lookup to trigger `stack.sync_github` on every matching stack: [7](#0-6) 

The `status` handler is worse: it doesn't even key off `full_name`, it matches purely on commit `sha` across the entire instance, with no repository scoping at all: [8](#0-7) 

Since Shipit supports multiple GitHub organizations each with their own `webhook_secret` in the same config (`config/secrets.yml`'s `github:` block keyed by org), an operator/admin of Organization A (who legitimately knows Organization A's `webhook_secret` because they configured Organization A's GitHub App) can craft an arbitrary JSON body where `repository.owner.login` = "OrgA" (so `verify_signature` selects and validates against Organization A's secret) while `repository.full_name` or the target `sha` refers to a completely different, unrelated organization's repository/commit tracked by the same Shipit instance. The HMAC only certifies "signed by whoever holds Org A's secret" — it does not certify "this event genuinely originates from Org A's repository" for the fields the handlers actually consume.

### Impact Explanation
- Via the `status` event, an attacker holding one org's `webhook_secret` can forge a "success"/arbitrary CI status for any known commit `sha` in any repository/stack tracked by the Shipit instance (`Commit.where(sha:).each { |c| c.create_status_from_github!(params) }`), independent of which org that commit belongs to. If deploy or merge gating in this Shipit deployment relies on GitHub commit statuses (a common Shipit-managed CI/CD workflow), this allows spoofing the checks required to authorize a deploy for a stack the attacker does not otherwise control.
- Via the `push` event, the same holder can trigger `Stack#sync_github` (github sync) for any stack whose repository `full_name` they choose to embed in the forged payload, regardless of which org's secret validated the request.
- Via the `pull_request` events, similarly-scoped `Repository.from_github_repo_name(params.repository.full_name)` lookups drive review-stack provisioning/archival, again decoupled from the authenticating organization.

This satisfies the "unauthorized deploy" / cross-repository-writes class of Critical/High impact: an entity trusted only for its own organization's webhook traffic can act on state belonging to a different organization's repositories/stacks within the same instance.

### Likelihood Explanation
Requires the multi-organization configuration (`github: { orgA: {...webhook_secret...}, orgB: {...} }`) documented in `docs/setup.md`/`config/secrets.development.shopify.yml`, and requires the attacker to already legitimately possess one org's `webhook_secret` (e.g., they administer that org's GitHub App installation in a shared Shipit deployment). This is a realistic operational configuration for organizations that run one shared Shipit instance across multiple GitHub orgs/teams, which is exactly the scenario the multi-org config exists for.

### Recommendation
After computing `repository_owner` for signature verification, re-validate that the same owner is consistent with every "repository"-bearing field the handlers subsequently use (`repository.full_name`, and for `status` events, scope the `Commit.where(sha:)` lookup to commits belonging to stacks/repositories owned by `repository_owner`). Reject the webhook if there is any mismatch between the organization whose secret validated the signature and the repository/commit the event claims to describe.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `orgA` and `orgB`, each with its own `webhook_secret` (a supported, documented configuration).
2. As an operator who legitimately knows `orgA`'s `webhook_secret` (e.g., they set up `orgA`'s GitHub App), craft a `status` event body:
```json
{
  "sha": "<sha of a commit belonging to orgB/some-repo tracked in the same instance>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgA/decoy" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>` and POST to `/github/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"orgA"`, fetches `orgA`'s `GitHubApp`, and the signature validates successfully.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the `orgB` commit regardless of the `orgA` binding used to authenticate the request — and calls `create_status_from_github!`, injecting a forged CI status onto `orgB`'s commit.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
