### Title
Webhook signature is verified against the organization named in the payload, not the repository that is actually mutated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController` selects which GitHub App/organization secret to use for HMAC verification from `params.dig('repository','owner','login')` (or `organization.login`), but the handlers that subsequently act on the payload resolve the target repository/commit independently — in most handlers from `payload.dig('repository','full_name')`, and in `StatusHandler` from the commit `sha` alone with no repository scoping at all. Because these two lookups are never cross-checked, a payload can be crafted so that the *field used to select the verification secret* and the *field(s) used to decide what gets written* refer to different organizations/repositories.

### Finding Description
`verify_signature` picks the GitHub App config to validate against using only the owner login: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves per-organization app configs, and each organization's `GitHubApp#verify_webhook_signature` treats a blank `webhook_secret` as automatically verified: [3](#0-2) [4](#0-3) 

The engine explicitly supports multiple organizations each with their own independent `webhook_secret`, including organizations configured with **no** secret at all (`webhook_secret: # nil`), as shown in the fixture used to test multi-org support: [5](#0-4) [6](#0-5) 

Once `verify_signature` passes (trivially, if the organization named in `repository.owner.login`/`organization.login` has no configured `webhook_secret`), the raw JSON body is dispatched unmodified to handlers: [7](#0-6) 

Generic handlers resolve the target repository/stack from `repository.full_name` — a different field than the one used for signature selection, and never re-validated against `repository.owner.login`: [8](#0-7) 

`StatusHandler` is worse: it does not even scope by repository — it looks up `Commit` globally by `sha` across the entire installation and writes a forged CI status: [9](#0-8) 

**Trust binding broken:** `organization authenticated by verify_signature` should equal `organization/repository whose data the handler mutates`. Before the fix this equality holds only by convention (both fields normally come from the same real GitHub delivery); it is never enforced in code, so an attacker who controls the raw payload can decouple the two.

### Impact Explanation
An attacker who knows (or can probe for) any organization in the deployment's multi-org GitHub config that has no `webhook_secret` set — a supported, documented configuration, not a misconfiguration outside the engine's control — can submit an unsigned/arbitrarily-signed webhook whose `repository.owner.login` (or `organization.login`) names that unsecured org, while `repository.full_name` (or, for `status` events, simply an arbitrary `sha`) targets a completely different, secured stack/repository. This lets an unauthenticated network attacker:
- Forge `status`/`check_suite` events to set a passing CI status on arbitrary commits in any stack (`StatusHandler`, `CheckSuiteHandler`), which gates the "Ready to ship" / merge-queue / deploy-readiness logic surfaced by `MergeStatusController`.
- Forge `push` events referencing another org's `repository.full_name` to enqueue `GithubSyncJob` for that stack.
- Forge `membership`/`pull_request` events to create teams/users or mutate `PullRequest` state for repositories unrelated to the org that "authenticated" the request.

This crosses the "unauthorized deploy/merge" impact bar because forged green commit statuses/check suites directly influence automated ship/merge decisions gated on GitHub status, and `push` forgery can trigger sync/deploy jobs for stacks belonging to organizations the attacker never authenticated against.

### Likelihood Explanation
Requires no session, no `ApiClient` token, and no knowledge of any *targeted* org's `webhook_secret` — only that at least one organization in the multi-org config has no secret configured (a supported deployment pattern per the engine's own fixtures/docs), which is externally discoverable by sending trial payloads and observing whether they are accepted (HTTP 200 vs 422). The webhook endpoint is intentionally public and unauthenticated by design (`skip_before_action :verify_authenticity_token`), so the only obstacle is the decoupled owner/full_name (or owner/sha) fields, which the engine never cross-validates.

### Recommendation
In `WebhooksController#verify_signature`, and in each `Handler`, derive the organization used for signature verification and the repository/stack used for mutation from a single, consistently-scoped source, and reject the payload if `repository.owner.login` does not match the owner implied by `repository.full_name`. For `StatusHandler`/`CheckSuiteHandler`, scope the `Commit`/stack lookup by the verified repository instead of a bare, global `sha` match.

### Proof of Concept
1. Deploy configures two orgs: `OrgOne` (no `webhook_secret`) and `OrgTwo` (has stacks with real repositories and a strong secret) — a configuration directly modeled by `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<victim-stack-head-sha-in-OrgTwo>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgOne" } }
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgOne")`; because `OrgOne.webhook_secret` is blank, `verify_webhook_signature` returns `true` unconditionally regardless of the (missing/invalid) `X-Hub-Signature` header.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim commit in `OrgTwo`'s stack regardless of which org "authenticated" the request — and calls `create_status_from_github!`, writing a forged passing status that can flip merge/deploy readiness for a repository the attacker never had credentials for. [10](#0-9) [9](#0-8)

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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
