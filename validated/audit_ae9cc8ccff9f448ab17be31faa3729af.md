### Title
Webhook signature verification is optional, allowing unauthenticated forgery of commit-status/push/membership events that gate deploys - (File: `lib/shipit/github_app.rb`)

### Summary
Shipit's webhook signature check silently no-ops when `webhook_secret` is not configured for the organization derived from the incoming (unverified) payload, and the organization used to pick the verification secret is itself read from that same untrusted JSON body. This mirrors the report's core bug class — a value the system trusts (which "organization authenticated" this request) is never actually bound to a verified credential, while the repository/commit state that gets written is driven by the identical unverified field.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/secret to check against using a field taken straight from the unparsed, unauthenticated request body: [1](#0-0) [2](#0-1) 

The actual verification, in `GitHubApp#verify_webhook_signature`, unconditionally returns `true` when no `webhook_secret` is configured for that organization: [3](#0-2) 

The setup documentation and example secrets file explicitly present `webhook_secret` as **optional**, with `nil` as the shown default: [4](#0-3) [5](#0-4) 

Once past this check, `WebhooksController#create` dispatches the identical, still-untrusted JSON body to handlers such as `StatusHandler`, which writes a `Status` record (including attacker-chosen `state`, `context`, `target_url`) onto an existing commit purely based on the `sha` field in that same payload: [6](#0-5) 

This breaks the binding: **"GitHub organization that cryptographically authenticated the delivery" = "repository/commit state the handler is permitted to write."** With no secret configured (a documented, supported configuration), the left side of that equation is never established at all — any unprivileged network client can POST directly to `/webhooks` and have it treated as a legitimate delivery from GitHub for that organization.

### Impact Explanation
An attacker with no session, no `ApiClient` token, and no repository access can forge a `status`/`commit_status` webhook marking any commit (including an unreviewed, malicious, or CI-failing one) as `success`. Shipit's deploy gating relies on these `Status` records to decide whether a commit is deployable, so this allows an unauthorized/unsafe commit to appear deployable, enabling an operator (or an auto-deploy pipeline) to ship it — an unauthorized deploy per the accepted impact criteria. It can equally forge `push` (queuing sync jobs), `membership` (creating teams/users), or `pull_request`/`merge` events, all without presenting any credential.

### Likelihood Explanation
This requires only that a Shipit deployment (single- or multi-org) is running with `webhook_secret` unset for at least one configured organization — a state the project's own setup guide labels "optional," not a misconfiguration outside the documented deployment model. No GitHub App private key, session, or `ApiClient` secret is needed; the attacker only needs to know the target's `/webhooks` URL and craft a JSON body, which is public information for any Shipit instance.

### Recommendation
Make `webhook_secret` mandatory rather than optional, and refuse to boot (or refuse to process any webhook) for an organization missing a configured secret rather than silently returning `true` in `verify_webhook_signature`. Additionally, do not use unauthenticated payload fields (`repository.owner.login`) to select the verification secret before the signature has itself been validated; instead, verify against all configured secrets/keys, or bind the secret lookup to a value that cannot be spoofed prior to verification.

### Proof of Concept
1. Deploy Shipit with a `config/secrets.yml` following the documented example, omitting `webhook_secret` (as shown in `config/secrets.development.example.yml`).
2. As an unauthenticated attacker, send:
```
POST /webhooks HTTP/1.1
X-Github-Event: status
Content-Type: application/json

{"sha":"<victim-commit-sha>","state":"success","context":"ci/build","target_url":"http://evil","repository":{"full_name":"victim-org/victim-repo","owner":{"login":"victim-org"}}}
```
No `X-Hub-Signature` header is required to pass validation because `verify_webhook_signature` returns `true` when `webhook_secret` is blank (`lib/shipit/github_app.rb:76-83`).
3. `StatusHandler` processes the forged payload and creates a `success` `Status` on the targeted commit, which can be leveraged by Shipit's deploy-eligibility checks to permit deployment of that commit.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-24)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end
```
