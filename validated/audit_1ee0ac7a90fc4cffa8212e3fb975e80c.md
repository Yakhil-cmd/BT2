### Title
Webhook signature is verified against `repository.owner.login`, but the handler acts on the unrelated `repository.full_name` field of the same forged payload - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify a webhook against using one field of the attacker-supplied JSON body (`repository.owner.login`), while `Webhooks::Handlers::Handler#repository_name` (used by every handler, e.g. `PushHandler`) resolves the `Stack`/`Repository` to act on using a *different* field of the same body (`repository.full_name`). Nothing binds these two fields together, so the identity that is authenticated is not the identity that is acted upon.

### Finding Description
The webhook signature check is: [1](#0-0) 

`repository_owner` is derived purely from the untrusted JSON body: [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns the `GitHubApp` configuration (and thus `webhook_secret`) for whatever organization name is embedded in `repository.owner.login`. Critically, `verify_webhook_signature` **short-circuits to `true` when that organization has no `webhook_secret` configured**, which is an explicitly documented/example configuration state: [3](#0-2) [4](#0-3) 

Meanwhile, every webhook handler resolves *which repository/stack to act on* using a completely different field of the same JSON body: [5](#0-4) 

`PushHandler` uses this to find matching stacks and immediately queues a sync using attacker-controlled `ref`/`after`: [6](#0-5) 

Equality that should hold but doesn't:
`verified_identity(repository.owner.login)` == `acted_repository(repository.full_name)`

Nothing in `WebhooksController` or `Handler` enforces that `repository.full_name` starts with `repository.owner.login`. An unauthenticated party can therefore POST directly to the public `/webhooks` endpoint (no session, no `ApiClient` token, no repository access needed) with a body where:
- `repository.owner.login` = an organization configured in `Shipit.github` with `webhook_secret: nil` (a state the project's own example configs ship with), which makes `verify_signature` pass unconditionally regardless of the `X-Hub-Signature` header sent, and
- `repository.full_name` = any other organization/repository actually tracked by the same Shipit instance (e.g. a stricter org that does have a real secret configured, since one Shipit deployment can host multiple orgs — see `config/secrets.development.shopify.yml`).

This is exactly the class of binding break called out in scope: "an organization that authenticated versus the repository that is written."

### Impact Explanation
The forged, unauthenticated request reaches `PushHandler#process`, which calls `stack.sync_github(expected_head_sha: params.after)` for every not-archived stack of the victim repository/branch chosen by the attacker, using an attacker-chosen `after` SHA and `ref`. Any Shipit stack that is continuously-deployed off that branch will act on this out-of-band synchronization signal, without the attacker ever having any credential, GitHub permission, or Shipit session tied to the victim repository — i.e. it is an unauthorized cross-organization trigger of stack activity that was supposed to require a validly-signed webhook scoped to that repository's own organization/secret.

### Likelihood Explanation
Exploitability is gated on at least one organization in the Shipit deployment's `Shipit.github` config having `webhook_secret` unset — a state explicitly present in this repo's own example/development secrets templates (`webhook_secret: # nil`), so it is a realistic operational configuration, not a contrived edge case. When present, the attack requires zero credentials and zero repository access — only knowledge of the target repository's `full_name` and that the Shipit instance also serves an org without a webhook secret.

### Recommendation
- Verify the webhook signature using the same field that handlers subsequently trust for repository resolution, and reject the request if `repository.full_name`'s owner segment does not match the organization whose secret validated the signature.
- Do not allow signature verification to succeed unconditionally (`return true unless webhook_secret`) for events carrying a `repository`/`organization` payload that differs from the org being verified; either require every configured org to have a secret, or bind verification explicitly to `repository.full_name`'s owner rather than a separately-read field.

### Proof of Concept
Given a Shipit deployment configured with two orgs, e.g.:
```yaml
github:
  attacker_org:
    webhook_secret: # nil
  victim_org:
    webhook_secret: "s3cr3t"
```
An unauthenticated attacker sends, with no valid `X-Hub-Signature` (or a bogus one):
```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker_org" },
    "full_name": "victim_org/victim-repo"
  }
}
```
`verify_signature` resolves `Shipit.github(organization: "attacker_org")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb` lines 76-77) regardless of the signature header. `PushHandler#process` then resolves stacks via `payload.dig('repository','full_name')` = `"victim_org/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb` lines 36-38) and calls `stack.sync_github(expected_head_sha: "deadbeef...")` for that stack — an action the attacker was never authorized to trigger for `victim_org`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L7-23)
```ruby
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
```
