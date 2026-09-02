Based on my investigation, I found a genuine binding-break analog in `WebhooksController`, but I was unable to fully confirm the downstream repository-resolution code in `push_handler.rb` before running out of tool calls (only got a grep hit, not file content). I'll present the finding based on what I *did* confirm directly, and flag the remaining uncertainty explicitly.

### Title
Webhook signature verification is routed by an unverified `repository_owner`/`organization.login` field, allowing spoofed events to bypass authentication for any org configured without a `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which `GithubApp` config (and therefore which `webhook_secret`) to verify a webhook against, using a field taken directly from the unauthenticated request body — `repository_owner` — rather than any value covered by the signature itself. [1](#0-0)  Combined with `verify_webhook_signature` unconditionally returning `true` when no `webhook_secret` is configured for that org, [2](#0-1)  this creates the equality break: `organization used to select the verifier` ≠ `organization/repository the payload actually claims to act on`.

### Finding Description
`repository_owner` is read straight from the JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`) before any cryptographic check occurs. [3](#0-2)  This value is used solely to pick which `Shipit.github(organization:)` config verifies the signature. If a Shipit deployment configures multiple GitHub orgs (a supported configuration, as shown in `test/dummy/config/secrets_double_github_app.yml`, where `OrgTwo` has `webhook_secret: # nil`), any org lacking a configured secret makes `verify_webhook_signature` a no-op that returns `true` regardless of the `X-Hub-Signature` header supplied. [4](#0-3) 

An unauthenticated attacker (no session, no API token, no webhook secret) can therefore submit a forged webhook body whose `repository.owner.login` matches the secret-less org (satisfying `verify_signature`), while other payload fields consumed later by the event handlers (e.g. `repository.full_name`, branch, commit `sha`) reference an entirely different, real repository/stack tracked by Shipit. The signature check only binds the *authentication path selection*, not the data actually processed by `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [5](#0-4) 

**Caveat on completeness:** I was not able to retrieve the full contents of `app/models/shipit/webhooks/handlers/push_handler.rb` before this investigation ended, so I cannot cite the exact line where `repository.full_name` (or equivalent) is used to resolve the target `Stack`/`Repository` independent of `repository_owner`. This is required to fully prove that the acted-upon repository can diverge from the org used for verification. Without that confirmation, I cannot certify this as a fully proven, exploitable cross-repository write — it is a strong, plausible analog to the reported bug class (a field consumed by downstream logic that isn't covered by the verification check) but the concrete impact (e.g., forging a `push` event that triggers `GithubSyncJob`/commit-status writes for a legitimate, unrelated stack) rests on handler code I could not confirm in this session.

### Impact Explanation
If confirmed, this would allow an unauthenticated network attacker to inject spoofed GitHub events (push, status, check_suite, membership, pull_request) that are processed as if verified, potentially creating unauthorized commit statuses, membership/team changes, or influencing `GithubSyncJob` state for a tracked stack — without ever needing a Shipit session, API token, or the real `webhook_secret` for the targeted org.

### Likelihood Explanation
Likelihood depends entirely on deployment configuration: it requires a multi-org GitHub App setup where at least one configured organization intentionally or accidentally omits `webhook_secret` (explicitly supported/documented as `webhook_secret: # nil`). In a single-org deployment with a secret configured, this path is not exploitable.

### Recommendation
- Do not use an unauthenticated request field (`repository_owner`) to select the verification key when other configured orgs use signatures; require a secret-derived value or verify against all configured orgs' secrets rather than routing by attacker-supplied data.
- Reconsider allowing `webhook_secret` to be blank/optional in multi-org configurations, or require that all orgs in a shared install use secrets when more than one org is configured.
- Ensure webhook event handlers independently validate that `repository.full_name` (or organization) in the payload matches a `Repository`/`Stack` actually associated with the verified organization, rather than trusting the payload's own repository fields.

### Proof of Concept
1. Configure Shipit with two GitHub orgs: `OrgOne` (real org, tracked stacks, `webhook_secret` set) and `OrgTwo` (`webhook_secret` left blank), as shown in the dummy fixture. [4](#0-3) 
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature`, and a JSON body where `repository.owner.login = "OrgTwo"` but `repository.full_name` references a stack actually tracked under `OrgOne`.
3. `verify_signature` calls `Shipit.github(organization: "OrgTwo")`, whose `verify_webhook_signature` short-circuits to `true` because `webhook_secret` is blank. [6](#0-5) 
4. The forged payload proceeds to `Shipit::Webhooks.for_event('push')` handlers unchecked against the real signature that `OrgOne` would require. [5](#0-4) 

*Note: step 4's actual effect on an `OrgOne` stack could not be fully verified in this session because `push_handler.rb`'s repository-resolution logic was not retrieved; a background Devin session with full file access should confirm whether the push handler resolves the target stack via `repository.full_name` independent of `repository_owner`, which would fully validate cross-repository impact.*

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
