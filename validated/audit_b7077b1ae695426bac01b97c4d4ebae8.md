Confirmed the multi-tenant lookup path. Now I have enough to write the analog finding.

### Title
Webhook signature verified against the wrong organization's secret while repository actions are keyed by an unrelated, attacker-supplied `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` derives *which* GitHub organization's webhook secret to check against from an attacker-controlled JSON field (`repository.owner.login` / `organization.login`), while the handlers that actually act on the payload (writing state, triggering syncs/deploys) key off a *different* field in the same payload, `repository.full_name`. In a multi-tenant Shipit install (`Shipit.github_organizations`/`github_app_config`), these two fields are never cross-checked, so the org whose secret is verified need not be the org that owns the repository being mutated.

### Finding Description
`verify_signature` in [1](#0-0)  computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is [2](#0-1) :
```ruby
params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
```
`Shipit.github(organization:)` resolves per-tenant config via `github_app_config(organization)` in [3](#0-2) , and `GitHubApp#verify_webhook_signature` in [4](#0-3)  returns `true` unconditionally when that org's `webhook_secret` is blank:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```
Sample multi-org configuration in this engine explicitly allows a tenant with `webhook_secret: # nil` alongside other tenants that do have a secret (`config/secrets.development.shopify.yml`), which is the documented supported shape for `Shipit.github_organizations`.

Once the request passes `verify_signature`, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs handlers such as `PushHandler`, which resolve the target repository purely from `payload.dig('repository', 'full_name')` via the shared `Handler#stacks` helper: [5](#0-4) 
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
`PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on every matching, non-archived stack for the parsed branch [6](#0-5) .

The trust binding that should hold is:
`organization whose secret authenticated the request == organization that owns the repository whose stacks are mutated by the handler`

Because `repository.owner.login` (used only for secret selection) and `repository.full_name` (used only for the actual write target) are two independent, unauthenticated-at-selection-time fields inside the same attacker-supplied JSON body, an attacker can set them to point at *different* organizations. If any organization configured in this Shipit instance has `webhook_secret` blank/nil (a state the engine's own sample config and `GitHubApp#verify_webhook_signature` explicitly support), an unprivileged network attacker can:
1. Set `repository.owner.login` (or `organization.login`) to the name of the no-secret tenant, so `verify_webhook_signature` short-circuits to `true` with no signature required at all.
2. Set `repository.full_name` to any other tenant's real tracked repository (e.g. `victim-org/victim-repo`).
3. Send an arbitrary `push`/`status`/`check_suite`/etc. payload; the corresponding handler acts on the victim repository's stacks using attacker-chosen fields (e.g. `after` SHA for `sync_github`, commit `state`/`target_url` for statuses, `check_suite` conclusions, etc.), with no valid signature from the victim org ever presented.

### Impact Explanation
This breaks the authentication boundary the webhook signature is meant to provide: an attacker who knows nothing about a victim organization's `webhook_secret` can still make cross-organization, state-mutating calls into that organization's stacks (triggering `GithubSyncJob`, injecting commit statuses, or driving deploy-gating decisions) merely by targeting a differently-configured, secret-less tenant on the same shared Shipit deployment. This is a cross-repository/cross-organization write achieved without any credential for the affected repository, matching the "cross-repository writes" / "unauthorized deploy" impact class for this engine (deploys are gated on synced commits and CI status that this path can influence).

### Likelihood Explanation
Exploitability depends entirely on the operator's multi-tenant configuration containing at least one organization entry with an empty `webhook_secret` — a configuration shape the engine itself documents and ships as an example (`config/secrets.development.shopify.yml`, `docs/setup.md`). Any such installation is exposed to this cross-organization spoofing with zero attacker privileges, no token, and no GitHub-side access — only knowledge of the org name string, which is often public (e.g. visible in the Shipit UI or via prior legitimate webhook traffic).

### Recommendation
Do not let `repository.full_name`/handler-visible fields diverge from the organization whose secret validated the request. Concretely:
- Require every configured GitHub organization to have a non-blank `webhook_secret` (fail closed instead of `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature`).
- After signature verification, assert that `repository.owner.login` (the org used to select the secret) matches the owning organization of every repository resolved from `repository.full_name` before handlers run, rejecting mismatches with `422`.

### Proof of Concept
Given a multi-tenant `secrets.yml` with:
```yaml
github:
  attacker_org:
    app_id: 1
    installation_id: 1
    webhook_secret: # blank
  victim_org:
    app_id: 2
    installation_id: 2
    webhook_secret: "real-secret"
```
and a Shipit stack tracking `victim_org/victim-repo`, send (no `X-Hub-Signature` header needed):
```http
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "attacker_org" }, "full_name": "victim_org/victim-repo" }
}
```
`verify_signature` calls `Shipit.github(organization: "attacker_org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally. `PushHandler` then resolves `Repository.from_github_repo_name("victim_org/victim-repo")` and enqueues `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for the victim's stacks, all without ever presenting `victim_org`'s webhook secret.

### Citations

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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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
