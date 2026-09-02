This confirms the critical binding mismatch. The `Handler` base class resolves the target `Repository`/`Stack` using `payload.dig('repository', 'full_name')` [1](#0-0) , while `WebhooksController#verify_signature` selects which GitHub App/secret to verify against using a *different* field: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) .### Title
Webhook authentication binds to `repository.owner.login`/`organization.login` while write targeting binds to a separate, unchecked `repository.full_name` field — enabling cross-organization/cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports hosting multiple independently-configured GitHub Apps/organizations, each with its own `webhook_secret` [3](#0-2) . Which secret is used to validate an inbound webhook's HMAC signature is selected from a field inside the *unauthenticated* JSON body (`repository.owner.login` / `organization.login`), while the object that is actually looked up and mutated by the event handlers is selected from a *different* field in that same body (`repository.full_name`). These two fields are never cross-checked against each other, so authenticating as organization A does not guarantee the handler only acts on organization A's repositories.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to verify against using: [4](#0-3) 
and derives the organization solely from: [2](#0-1) 

Once verification passes, `WebhooksController#create` dispatches the raw, attacker-controlled JSON body to the registered handler(s) unchanged: [5](#0-4) 

Every handler resolves the target `Stack`/`Repository` from a **different** field of the same payload: [1](#0-0) 

`Repository.from_github_repo_name` splits this into owner/name and looks the record up directly, with no reference to whatever organization was used for signature verification: [6](#0-5) 

`PushHandler#process` then acts on whatever stacks match that repository: [7](#0-6) 

**The broken equality:** `verified_organization (repository.owner.login / organization.login, used to select the HMAC secret) == organization_of_repository_acted_upon (repository.full_name, used by Handler#stacks)` is never enforced.

An attacker who legitimately controls a GitHub App installation for *their own* organization (`attacker-org`), configured in the same Shipit instance (a normal, unprivileged, multi-tenant setup per `docs/setup.md`/`secrets.development.example.yml`), knows `attacker-org`'s `webhook_secret`. They can craft a webhook payload where:
- `repository.owner.login` = `attacker-org` (or `organization.login` = `attacker-org` for events that fall back to it) — so `Shipit.github(organization: repository_owner)` resolves to `attacker-org`'s `GithubApp`, whose secret the attacker knows, so `verify_webhook_signature` succeeds using an HMAC the attacker legitimately computed.
- `repository.full_name` = `victim-org/victim-repo` — a completely different, unrelated organization's repository that the attacker has no access to.

Because `Handler#repository_name`/`#stacks` only reads `repository.full_name` and never reconciles it with the organization that was actually authenticated, the forged event is processed against `victim-org/victim-repo`'s stacks with full trust.

### Impact Explanation
This is a cross-repository/cross-organization write achieved purely through an authentication field mismatch — no access to the victim's repository, GitHub App, or webhook secret is required, only knowledge of the attacker's own (unprivileged) org's webhook secret. Depending on event type this can:
- Force `PushHandler` to enqueue `GithubSyncJob`/`sync_github` on the victim stack with an attacker-chosen `expected_head_sha` [7](#0-6) , injecting commit/sync state into a stack the attacker does not own.
- Forge `status`/`check_suite` webhooks that write `Status`/check-run records against arbitrary commits in the victim's stack, which downstream CI-gating logic in Shipit relies on to permit deploys.
- Forge `membership` events that create/delete `Team`/`Membership` rows outside the attacker's authority since the same `repository_owner`/`organization.login` mismatch applies there too.

This matches the "cross-repository writes" Critical-impact category and can be leveraged toward influencing what commits/statuses look deployable on a stack the attacker does not control.

### Likelihood Explanation
Medium-to-high in any Shipit deployment that hosts more than one GitHub organization's repositories (an explicitly documented and supported configuration). The attacker only needs administrative control of one, even a throwaway, org+GitHub-App entry configured on the same Shipit instance — no privileged GitHub org membership, no Shipit `ApiClient` token, and no access to the victim repository/organization is needed. The mismatch is triggered by a single crafted HTTP POST to `/webhooks` with a validly-signed-for-attacker-org body whose `repository.full_name` names a victim repo.

### Recommendation
After signature verification, re-derive the organization from the exact same field the handlers use for repository resolution (`repository.full_name`'s owner segment) and require it to equal the organization whose secret validated the signature, rejecting (422) any payload where these differ. Equivalently, `Handler#repository_name` should be cross-checked in the controller against `repository_owner` before dispatch, so that the authenticated org and the acted-upon repository's org are provably the same value.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.yml`, e.g. `attacker-org` (secret `S1`, controlled by attacker) and `victim-org` (secret `S2`, unknown to attacker), each hosting at least one `Stack`.
2. Attacker builds a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S1, body)` since they know `S1`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`), which succeeds against `S1`.
5. `Shipit::Webhooks.for_event('push')` invokes `PushHandler`, whose `Handler#repository_name` reads `repository.full_name` = `"victim-org/victim-repo"`, resolving and acting on `victim-org`'s actual stack — despite the request never being authenticated by `victim-org`'s secret.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
