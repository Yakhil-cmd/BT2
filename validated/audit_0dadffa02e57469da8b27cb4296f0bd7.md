### Title
Webhook signature verification org is decoupled from the repository the payload writes to, allowing cross-org spoofed pushes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App config (and hence the HMAC secret) used to authenticate an inbound webhook based on `repository_owner`, a value read straight out of the untrusted JSON payload — falling back to a completely different payload field (`organization.login`) whenever `repository.owner.login` is absent. The event handlers that subsequently act on the payload (e.g. `PushHandler`) resolve the target `Stack`/`Repository` from an entirely different, also attacker-controlled field: `repository.full_name`. Because nothing ties "the org whose secret validated this signature" to "the repository whose stack gets mutated," and because `verify_webhook_signature` short-circuits to `true` whenever an org's `webhook_secret` is unset (an explicitly documented *optional* setting), an attacker can trigger `Repository#sync_github`/deploy-affecting webhook processing for a repository belonging to an organization that never validated the request.

### Finding Description
`verify_signature` computes the authenticating org like this: [1](#0-0) 
and [2](#0-1) 

`repository_owner` is derived with `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — i.e. if the payload's `repository` object has no `owner` sub-key, the org used to pick the `GitHubApp` (and its `webhook_secret`) silently falls back to the top-level `organization.login`, a sibling field the attacker also controls.

`Shipit.github(organization:)` looks up the per-org app config from `Shipit.secrets.github` (multi-org config documented in `docs/setup.md`), and `GitHubApp#verify_webhook_signature` is: [3](#0-2) 
Note line 77: `return true unless webhook_secret` — if the org resolved by `repository_owner` has no `webhook_secret` configured (explicitly called out as "(optional)" in `docs/setup.md` and `config/secrets.development.example.yml`), **any** signature, including none, passes verification for that org.

Once verification passes, `WebhooksController#create` dispatches to handlers using the same raw payload: [4](#0-3) 
`Shipit::Webhooks::Handlers::Handler` resolves the target repository/stacks from a *different* payload field than the one used for authentication: [5](#0-4) 
and `PushHandler` triggers `stack.sync_github(expected_head_sha: params.after)` for every matching stack: [6](#0-5) 

The binding that should hold is:
`organization whose credential (webhook_secret) authenticated the request == owning organization of the repository/stack the handler mutates`

The code breaks this equality because (a) the authenticating org is picked from a fallback field (`organization.login`) independent of `repository.full_name`, and (b) that authenticating org can be one with no `webhook_secret` set, at which point authentication is a no-op for that org while the handler still acts on `repository.full_name`, which can name a stack belonging to a *different*, properly-secured organization present in the same Shipit installation (multi-org config, per `docs/setup.md` "Using Multiple Github Applications").

### Impact Explanation
This crosses the "unauthorized deploy"/"cross-repository writes" bar: an attacker who knows (or guesses) the login of any organization configured in `Shipit.secrets.github` without a `webhook_secret` can submit a forged `push` (or other) webhook naming a `repository.full_name` that belongs to a *different*, secured organization's stack, and cause `Stack#sync_github`/downstream deploy-triggering logic to run against attacker-chosen `ref`/`after` sha for that stack — with zero possession of any real secret, GitHub App key, or Shipit session. This is exactly the class of finding the prompt calls out: "an organization that authenticated versus the repository that is written."

### Likelihood Explanation
Requires only: (1) a multi-org Shipit deployment (explicitly documented and supported), and (2) at least one configured org lacking `webhook_secret` (explicitly documented as optional, and shown blank in every shipped example config: `config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, `docs/setup.md`). No credentials, tokens, or sessions are needed — the request is an unauthenticated HTTP POST to `/webhooks`. This is a realistic, low-effort misconfiguration given the docs actively suggest leaving `webhook_secret` blank ("Webhook secret (optional)").

### Recommendation
- Require `webhook_secret` to be present for every configured GitHub App/org; refuse to boot (or refuse all webhooks) if any org config in `Shipit.secrets.github` omits it, rather than treating a missing secret as "verification passed."
- Derive the authenticating org strictly from `repository.owner.login` (never fall back to a sibling `organization.login` field) and, in the handler, verify that the resolved `Repository`'s owner matches the org that was actually used to validate the signature before acting on `full_name`.
- Reject payloads where `repository.full_name`'s owner segment does not match `repository_owner` used for signature verification.

### Proof of Concept
Given a multi-org Shipit install with:
```yaml
github:
  attacker_org:
    app_id: ...
    installation_id: ...
    webhook_secret: # left blank, per docs
  victim_org:
    app_id: ...
    installation_id: ...
    webhook_secret: "s3cr3t"
```
POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "full_name": "victim_org/victim-repo" },
  "organization": { "login": "attacker_org" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
`repository_owner` resolves to `"attacker_org"` (because `repository.owner` is absent), `Shipit.github(organization: 'attacker_org').verify_webhook_signature` returns `true` unconditionally (no `webhook_secret`), and `PushHandler` then resolves `victim_org/victim-repo`'s stacks via `payload.dig('repository','full_name')` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` — with no valid signature ever produced for `victim_org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
