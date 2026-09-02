### Title
Webhook signature is verified against the organization in `repository.owner.login`, but handlers act on the independent `repository.full_name` field, letting anyone with one org's `webhook_secret` forge state changes on a different org's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App / `webhook_secret` to validate the inbound HMAC against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). [1](#0-0) [2](#0-1)  Once the signature check passes, every event handler resolves the *target* repository/stack from a completely different, unrelated field of the same payload: `payload.dig('repository', 'full_name')`. [3](#0-2) 

Because Shipit supports multiple GitHub organizations, each with its own independently configured `webhook_secret` (as documented in the multi-org secrets example), the field used to *authenticate* the request (`repository.owner.login`) and the field used to *authorize/act* on a resource (`repository.full_name`) are never bound to each other by the signature check. [4](#0-3)  The HMAC only proves "this exact byte sequence was signed with organization X's secret" - it does not constrain which repository name may appear inside that byte sequence.

### Finding Description
This is the direct analog of the reported bug class: the binding that should hold is
`organization that authenticated == repository that is written`,
but the code only enforces "some org's secret signed this raw body," while the actual mutation target is picked from a sibling JSON field that the signing organization does not constrain.

Concretely:
1. `verify_signature` picks `github_app = Shipit.github(organization: repository_owner)` using `repository.owner.login` from the payload, then checks the HMAC of the raw body against that org's `webhook_secret`. [1](#0-0) 
2. Handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) all inherit `stacks`/`repository_name` from `Handler`, which reads `payload.dig('repository', 'full_name')` - a field entirely independent from `repository.owner.login`. [3](#0-2)  `PushHandler#process` then queues a sync for whatever stacks belong to that `full_name`. [5](#0-4) 
3. An operator/attacker who is a legitimate admin of *their own* org "orgA" (with its own GitHub App and `webhook_secret` configured in this Shipit instance, per the documented multi-org config) can compute a valid `X-Hub-Signature` over an arbitrary JSON body of their choosing using orgA's secret. Nothing stops them from setting `repository.owner.login = "orgA"` (so signature verification picks orgA's secret and succeeds) while simultaneously setting `repository.full_name = "victim-org/victim-repo"` (so the handler acts on a stack that belongs to a completely different, unrelated organization/repository they do not control).

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary explicitly called out as in-scope. Depending on the event chosen, the attacker can:
- Trigger `GithubSyncJob` / forced sync on a victim stack via `push` events, and drive its `expected_head_sha`, potentially advancing deploy state on a repository they don't own. [5](#0-4) 
- Forge commit statuses (`status` event) or check-suite refresh events against a victim's commits, since `StatusHandler`/`CheckSuiteHandler` resolve the same way through `Handler#repository_name`. This can satisfy or manipulate CI-gating logic Shipit relies on before allowing a deploy, i.e., cross-repository write / unauthorized deploy influence.

This matches the High/Critical impact categories: escalation across a repository boundary using credentials the attacker only legitimately holds for a different, unrelated organization.

### Likelihood Explanation
Requires the attacker to have their own org onboarded to the same multi-tenant Shipit instance with a self-known `webhook_secret` - which is the documented, supported multi-org configuration, not a privileged/insider position with respect to the victim org. No access to the victim's secret, token, or session is needed; only knowledge of a signing key the attacker legitimately possesses for their own tenant. This satisfies the "unprivileged attacker breaking a deployment-trust binding" requirement.

### Recommendation
Bind the field used for authentication to the field used for authorization: after `verify_webhook_signature` succeeds for `repository_owner`, re-derive `repository_name`/target stack and assert its owner segment matches the same `repository_owner` used to select the secret (or better, resolve the target `Repository`/`Stack` and confirm its `owner`/org matches the authenticated org before invoking handlers), rejecting the request otherwise.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md` / `config/secrets.development.shopify.yml`) with two orgs: `orgA` (attacker-controlled, webhook_secret known to attacker) and `victim-org` (has a stack tracked in Shipit, e.g. `victim-org/victim-repo`). [4](#0-3) 
2. Attacker builds a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(orgA_webhook_secret, raw_body)` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "orgA")` and validates successfully because the signature does match orgA's secret over this exact body. [1](#0-0) 
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `sync_github(expected_head_sha: <attacker chosen sha>)` on the victim's stack - despite the request having been authenticated only against orgA's credentials. [3](#0-2) [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
