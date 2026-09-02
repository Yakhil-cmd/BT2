### Title
Webhook signature verification uses an attacker-influenced organization field that is decoupled from the repository field the event handlers actually act on - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App / `webhook_secret` to validate a request against by reading `repository.owner.login` (or `organization.login`) straight out of the still-unverified JSON body, then HMAC-checks the raw body with that app's secret. Every event `Handler`, however, decides *which* `Stack`/`Repository` to act on using a **different** field from the same body: `repository.full_name`. Nothing in the engine enforces that the organization used to select/verify the signature is the owner segment embedded in `full_name`. This is the same class of bug as the Cobb-Douglas report: a field that participates in the trust decision (`owner.login`, used to pick the secret) is disjoint from the field that is actually acted upon (`full_name`, used to pick the target repository), and the code never checks the two are consistent.

### Finding Description
- `verify_signature` resolves `repository_owner` from the raw body and fetches the matching app config via `Shipit.github(organization: repository_owner)`, then verifies the signature with that org's secret: [1](#0-0) [2](#0-1) 
- `GithubApp#verify_webhook_signature` returns `true` unconditionally whenever that particular organization's `webhook_secret` is blank/unset: [3](#0-2) 
- Every `Handler` (push, status, check_suite, membership, …) independently determines the target repository/stack from `repository.full_name`, a completely separate field of the same body, with no cross-check against the organization that was used for signature selection: [4](#0-3) 
- Multi-organization deployments, where each org has its own independent `webhook_secret` (including intentionally blank ones, since the secret is documented as optional), are an explicitly supported and documented configuration: [5](#0-4) [6](#0-5) 

Because the "which secret to check" decision and the "which repository to act on" decision each read a different, independently attacker-shaped field from the same unauthenticated JSON body, an attacker who can produce a validly-signed payload for **any one** configured organization (trivially possible if that organization has no `webhook_secret` configured, since verification is skipped entirely for it) can set `repository.owner.login`/`organization.login` to that weak/unsecured org while setting `repository.full_name` to a `stack` belonging to a **different, fully-secured** organization on the same Shipit instance. The equality the code implicitly (and incorrectly) assumes is:
`organization used to verify signature == owner(repository.full_name) acted on by the Handler`
This equality is never enforced anywhere in the engine; it only holds by convention because GitHub itself always produces internally-consistent payloads for legitimately-triggered events. It does not hold for an attacker who crafts the raw POST body directly.

### Impact Explanation
If this equality is broken, an unprivileged network attacker (holding no `ApiClient` token, no `webhook_secret`, no GitHub credentials of the target org) can forge `push`, `status`, `check_suite`, or `membership` events against a fully-secured organization's stacks by routing the signature check through a different, weaker/unset-secret organization also configured on the same Shipit instance. This can trigger `GithubSyncJob`/`stack.sync_github` on arbitrary target stacks (unauthorized sync/deploy triggers), inject forged commit `Status` records that CI/deploy gating relies on, or manipulate `Team`/`Membership` records — i.e., cross-repository writes and unauthorized deploy-adjacent actions on repositories the attacker does not control, which maps to the Critical/High impact classes defined in scope (cross-repository writes / unauthorized deploy).

### Likelihood Explanation
Exploitability is contingent on the specific deployment configuring multiple GitHub organizations (a documented, first-class feature) where at least one configured organization has a blank `webhook_secret` — itself explicitly permitted by the setup docs and the code's `return true unless webhook_secret` fallback. Given multi-org setups are a documented use case and per-org secrets are optional, this is a realistic, not purely theoretical, misconfiguration path rather than requiring the host application to deviate from documented usage.

### Recommendation
Bind the organization used for signature verification to the same repository field the handlers act on: derive `repository_owner` from `repository.full_name`'s owner segment (or otherwise validate that `repository.owner.login`/`organization.login` matches the owner encoded in `repository.full_name`) before dispatching to any `Handler`. Additionally, require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`), and validate the resolved `github_app.organization` against the actual repository being mutated inside `Handler#stacks`, not just inside the controller.

### Proof of Concept
1. Configure Shipit for two organizations per the documented multi-org setup: `org-weak` (no `webhook_secret` set) and `org-strong` (has a real stack and a real `webhook_secret`).
2. As an anonymous attacker with no credentials, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "org-weak" },
    "full_name": "org-strong/protected-stack"
  }
}
```
No `X-Hub-Signature` header (or an arbitrary one) is required, since `verify_webhook_signature` in `lib/shipit/github_app.rb:76-83` returns `true` unconditionally for `org-weak` (no secret configured).
3. `WebhooksController#verify_signature` passes (verified against `org-weak`'s absent secret), while `PushHandler`/`Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) resolves the target using `repository.full_name = "org-strong/protected-stack"`, enqueuing `GithubSyncJob` against `org-strong`'s protected stack despite the attacker never possessing `org-strong`'s webhook secret or any credentials for it.

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

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** docs/setup.md (L181-209)
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
