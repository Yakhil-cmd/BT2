### Title
Webhook signature bypass allows unauthenticated CI status forgery for arbitrary commits, defeating deploy CI gating - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
Shipit's webhook signature check derives which GitHub App/secret to verify against from an unauthenticated field of the very payload it is trying to verify, and silently treats a missing `webhook_secret` as "verified." Because `webhook_secret` is documented and shipped as an *optional* setting, an unauthenticated remote attacker can send a forged `status` webhook that is accepted without any valid signature, and the handler that processes it writes a commit status for **any** commit in the database, unscoped to the repository/organization claimed in the payload. This lets an attacker spoof a passing CI status for a commit, defeating the `ci.require` safety gate that blocks deploys of non-CI-passed commits.

### Finding Description
`WebhooksController#verify_signature` reads the organization used for signature verification straight out of the unverified request body: [1](#0-0) [2](#0-1) 

The resolved `github_app` is then asked to verify the signature via `GitHubApp#verify_webhook_signature`, which short-circuits to `true` whenever no `webhook_secret` is configured for that organization: [3](#0-2) 

`webhook_secret` is explicitly documented and shipped as optional (`nil` is a supported value), both in the setup docs and the default template/config examples: [4](#0-3) [5](#0-4) 

Once the request passes this (trivially bypassable) check, `WebhooksController#create` dispatches the raw JSON body to the registered handler for the event type without any further binding to the organization/repository that supposedly authenticated it: [6](#0-5) 

For the `status` event, `StatusHandler#process` looks up commits **purely by SHA**, with no scoping to a repository or stack that corresponds to the (attacker-controlled) `repository_owner`/`repository` fields used to select the "verifying" organization: [7](#0-6) 

This breaks the intended binding "the organization that authenticated == the repository/commit that is written": the identity used to decide trust (an org whose config may have no `webhook_secret`) is decoupled from the actual data mutated (any commit, in any stack, anywhere in the Shipit instance).

### Impact Explanation
Commit statuses reported through this path feed directly into the `ci.require` deploy gate described in Shipit's own configuration documentation — commits without the required passing statuses are blocked from being deployed: [8](#0-7) 

By forging a `status` webhook with a fabricated `state: "success"` for a target commit SHA, an unauthenticated attacker can satisfy `ci.require` for a commit that never actually passed CI, removing a security control that gates whether a deploy is permitted to proceed. This is an unauthorized-deploy-enabling primitive with no credential, session, or `ApiClient` token required — it only requires that the target Shipit instance has left `webhook_secret` unset for at least one configured organization, which is an explicitly supported, documented deployment configuration, not a misuse of the engine.

### Likelihood Explanation
Likelihood is high in any deployment that follows the documented "optional" `webhook_secret` setting: no credentials, GitHub org membership, or prior access are required. The attacker only needs the commit SHA of the target revision (visible in any public repository, PR, or the Shipit UI) and to know/guess the `repository_owner` value the operator's GitHub App is configured under (also discoverable from the Shipit instance's public pages, e.g. stacks/repositories listings).

### Recommendation
- Verify the webhook signature using a *fixed*, out-of-band-selected key (e.g., resolved from route/App configuration rather than payload-controlled fields), never trusting any field of the still-unauthenticated payload to select the verification key.
- Do not treat an absent `webhook_secret` as an automatic pass; require an explicit, secure `webhook_secret` for every configured GitHub App and reject requests when none is set, or otherwise strongly bind verification to a specific installation via the `X-GitHub-Hook-Installation-Target-ID`/App metadata instead of payload-supplied org/repo names.
- Scope `StatusHandler` (and other handlers keying off SHA alone) so that state changes are only applied to commits belonging to the stack/repository whose signature was actually verified.

### Proof of Concept
1. Target a Shipit instance where the operator followed the documented setup and left `webhook_secret` blank for the configured GitHub App (or for one org in a multi-org config).
2. Send:
```
POST /webhooks HTTP/1.1
X-Github-Event: status
Content-Type: application/json

{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "<configured-org>" } }
}
```
No `X-Hub-Signature` header is required (or any value works) since `verify_webhook_signature` returns `true` when `webhook_secret` is blank.
3. `StatusHandler#process` creates a "success" `Status` for `<victim-commit-sha>` regardless of which stack/repo it truly belongs to.
4. The `ci.require` gate on the stack now considers the commit deployable, allowing a deploy to proceed despite CI never having actually passed.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** README.md (L444-450)
```markdown
<h3 id="ci">CI</h3>

**<code>ci.require</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to disallow deploys if any of them is missing on the commit being deployed.

For example:
```yml
ci:
```
