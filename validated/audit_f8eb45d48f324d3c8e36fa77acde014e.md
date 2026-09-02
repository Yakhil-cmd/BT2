### Title
Webhook Signature Is Verified Against the Payload's `repository.owner.login`, But the Repository Acted On Is Selected From `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports multi-tenant GitHub App configuration, where several GitHub organizations can each have their own `webhook_secret` [1](#0-0) . The webhook signature check selects *which* organization's secret to validate against using `repository.owner.login` (or `organization.login`) taken directly from the untrusted JSON payload [2](#0-1) [3](#0-2) . However, once the signature is accepted, every webhook handler resolves the actual `Repository`/`Stack` to act on using a *different* payload field, `repository.full_name` [4](#0-3) . These two fields are never cross-checked against each other.

### Finding Description
`WebhooksController#verify_signature` picks the `GithubApp` (and thus the HMAC secret) to validate with, based on `repository_owner`: [2](#0-1) [3](#0-2) 

Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs the handlers over the raw, unmodified JSON body [5](#0-4) . Every handler's base class resolves the target stacks purely from `repository.full_name`, completely independent of `repository.owner.login`/`organization.login` used earlier for signature selection: [4](#0-3) 

For example, `PushHandler` triggers a GitHub sync job for any stack that has this `full_name` and matches the pushed branch/SHA [6](#0-5) , and `StatusHandler` creates a fabricated CI status on any existing commit matching the given SHA, independent of which repo/org it belongs to [7](#0-6) .

Because the field used to pick the *verifying* secret (`repository.owner.login`) and the field used to pick the *acted-upon* repository (`repository.full_name`) are two independent, attacker-controlled JSON keys in the same unsigned-structurally payload, an attacker who legitimately controls their own GitHub organization "OrgA" (with a Shipit-configured GitHub App/webhook_secret for OrgA) can sign a payload with `organization.login`/`repository.owner.login = "OrgA"` (so the signature check passes, since HMAC only verifies the byte string was signed with OrgA's secret — it does not enforce that `repository.full_name` also belongs to OrgA) while setting `repository.full_name = "OrgB/victim-repo"`, an entirely different tracked repository belonging to another team/org served by the same Shipit instance.

Binding broken (as equality that should hold but doesn't):
`organization authenticated by verify_signature (repository.owner.login) == repository written to by the handler (repository.full_name)`

### Impact Explanation
This lets an attacker who only controls a separate, unrelated GitHub organization onboarded to the same multi-tenant Shipit instance forge fully-signature-valid webhooks that act on a victim organization's stacks:
- Forge `status` events (`StatusHandler`) attaching fabricated passing CI statuses to a victim commit, which can satisfy `ci.require` checks and other automated CI-status decisions used for continuous deployment/merge gating — enabling an **unauthorized deploy** of a commit that never actually passed CI.
- Forge `push` events (`PushHandler`) to trigger `GithubSyncJob` against a victim stack's branch/SHA outside the victim org's control.

This crosses an authentication/authorization boundary between two mutually untrusted GitHub organizations hosted on the same Shipit instance, meeting the "unauthorized deploy" criterion for High/Critical impact.

### Likelihood Explanation
Requires only that the Shipit deployment be configured with multiple GitHub organizations (a documented, supported configuration pattern — see `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`), and that the attacker administers one of those organizations (able to configure their org's own webhook secret/GitHub App, which is standard for any onboarded org). No compromise of the victim org, no Shipit session, and no privileged Shipit account is required — only the ability to send a correctly-HMAC-signed webhook using credentials the attacker legitimately possesses for their own org.

### Recommendation
After signature verification, cross-validate that the organization inferred for signature verification (`repository.owner.login` / `organization.login`) matches the organization implied by `repository.full_name` (i.e., its owner segment) before dispatching to handlers. Alternatively, look up the `Repository` first by `full_name`, derive its associated GitHub organization/App, and use that same organization's secret for signature verification — removing the independent, attacker-controlled selection field.

### Proof of Concept
1. Configure/observe a Shipit instance with two orgs configured, `OrgA` and `OrgB` (multi-tenant `github:` config), where `OrgB/victim-repo` is a tracked Shipit stack.
2. As an administrator of `OrgA` (attacker-controlled), retrieve/know `OrgA`'s `webhook_secret` (it is the attacker's own org's secret, configured by the attacker when installing the App/webhook against Shipit).
3. Build a JSON payload for a `status` event:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "full_name": "OrgB/victim-repo", "owner": { "login": "OrgA" } }
}
```
4. Sign it with `HMAC-SHA1(OrgA_webhook_secret, payload)` and send as `X-Hub-Signature`, `X-Github-Event: status`.
5. `verify_signature` resolves `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and successfully verifies the signature since it was legitimately signed with `OrgA`'s secret.
6. `StatusHandler#process` matches `Commit.where(sha: params.sha)` for the victim commit (looked up independent of org) and calls `create_status_from_github!`, injecting a forged passing CI status onto `OrgB/victim-repo`'s commit — potentially unblocking an automated/continuous deploy that should have required a real CI pass.

### Citations

**File:** config/secrets.development.shopify.yml (L5-23)
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
    private_key:
    oauth:
      id:
      secret:
      teams:
```

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
