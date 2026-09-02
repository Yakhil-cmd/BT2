### Title
Webhook signature verification is keyed on `repository.owner.login` while every handler acts on the independent `repository.full_name` field, letting one authenticated GitHub organization forge events for another organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate a webhook against using `repository_owner`, a value read straight out of the untrusted JSON body (`repository.owner.login`, falling back to `organization.login`). All the actual webhook handlers, however, resolve the `Repository`/`Stack` to act on using a *different* field of the same body: `repository.full_name` (see `Shipit::Webhooks::Handlers::Handler#repository_name`). Because HMAC-SHA1 signs the raw body as an opaque blob, anyone who legitimately knows the webhook secret for *any one* configured GitHub organization in a multi-tenant Shipit install can construct a payload where `repository.owner.login`/`organization.login` names *their own* org (so the signature check passes using their own known secret) while `repository.full_name` names a repository belonging to an entirely different, unrelated organization also configured on the same Shipit instance.

### Finding Description
- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb` picks the app config to validate against based purely on attacker-controlled payload fields: [1](#0-0) [2](#0-1) 
- `Shipit.github(organization:)` supports a per-organization config map (`github: { org1: {...}, org2: {...} }`), each with its own independent `webhook_secret`, as documented in the multi-org example config: [3](#0-2) 
- Every handler that mutates state ignores `repository_owner` entirely and instead resolves the target repository/stack from `repository.full_name`, a sibling field in the same JSON body: [4](#0-3) 
- Concretely, `StatusHandler` writes a commit status purely from `params.sha`/`params.state`, with no cross-check that the commit's owning repository/org matches the org whose secret validated the request: [5](#0-4) 
- `PushHandler` likewise triggers a GitHub sync for any stack matching `repository.full_name` + branch, again without validating that this repository belongs to the organization identified by `repository_owner`: [6](#0-5) 
- `MembershipHandler` (creates/deletes `Team`/`Membership` rows feeding `User#authorized?` and `Shipit.github_teams` checks) is driven purely by webhook body content as well, per its own tests: [7](#0-6) 

**Binding broken (as an equality):** `organization authenticated by verify_signature (repository.owner.login / organization.login)` should equal `organization that owns the repository the handler writes to (repository.full_name)`. These two are read from independent, non-cross-validated fields of the same signed blob, so nothing enforces the equality; only the outer HMAC integrity is checked, not internal field consistency.

### Impact Explanation
An attacker who legitimately controls (or is an admin of) any one GitHub organization/App configured in a shared, multi-tenant Shipit instance can:
- Forge a `status` webhook targeting a commit SHA belonging to a *different* organization's stack, injecting a fabricated "success" CI status. If that stack has continuous deployment or status-gated deploys enabled, this can lead to an **unauthorized deploy** of a commit that never actually passed CI for that other organization/repository.
- Forge `membership` webhooks to create teams/memberships that are consumed by `Shipit.github_teams` authorization (`User#authorized?`), potentially escalating access to a Shipit-wide protected resource that was never intended to be controlled by that organization.
- Force sync/`GithubSyncJob` runs against a stack belonging to a different, unrelated organization by forging `push` events.

This matches the specified High-impact class: escalation into `Shipit.github_teams` authorization, and depending on stack configuration (status-gated continuous delivery), the Critical class of an unauthorized deploy.

### Likelihood Explanation
Exploitability requires only that the Shipit deployment is configured for more than one GitHub organization (a documented, supported configuration in `config/secrets.development.example.yml`) and that the attacker is a legitimate holder of one organization's own `webhook_secret` — not a privileged Shipit account, GitHub App private key, or any secret belonging to the victim organization. This is a realistic multi-tenant SaaS-style deployment scenario for Shipit.

### Recommendation
After signature verification succeeds, re-derive the authorized organization and assert that `repository.full_name`'s owner segment (and `organization.login`, if present) match the organization whose secret validated the signature, rejecting (422) any payload where these are inconsistent. Alternatively, pass the verified organization explicitly into each handler and have `Handler#repository_name`/`#stacks` filter by it instead of trusting the bare `repository.full_name` field.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (per `config/secrets.development.example.yml` multi-org format).
2. As an administrator of `attacker-org` (who legitimately knows `attacker-org`'s webhook secret because they configured the GitHub App), craft a `status` event payload:
```json
{
  "sha": "<victim-org commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Sign this payload with `attacker-org`'s webhook secret (`sha1=HMAC(payload, attacker_org_secret)`) and send it to `POST /webhooks` with header `X-Github-Event: status` and the computed `X-Hub-Signature`.
4. `WebhooksController#verify_signature` computes `repository_owner => "attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and the signature validates successfully (`app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `StatusHandler#process` then creates a commit status for the SHA in `victim-org/victim-repo` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`, `app/models/shipit/webhooks/handlers/handler.rb:32-38`), even though the request was never authenticated for `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** test/controllers/webhooks_controller_test.rb (L129-140)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end
```
