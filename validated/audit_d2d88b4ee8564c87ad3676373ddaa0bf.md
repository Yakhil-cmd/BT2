### Title
Cross-organization webhook forgery: signature verified against `repository.owner.login`'s org secret but writes are dispatched to the org/repo named in `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify a webhook against using `repository_owner`, a field read straight out of the *unverified* JSON body [1](#0-0) . That same body's `repository.full_name` field, used by every handler to look up the `Repository`/`Stack` to actually mutate, is a *separate, independently attacker-controlled* field [2](#0-1) . Nothing binds the two together, so a payload can be signed as belonging to organization A while its effects (push-triggered sync/deploy, forged CI status, etc.) are applied to a stack under an unrelated organization B.

### Finding Description
`repository_owner` is computed from the payload before the signature check occurs:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

`verify_signature` uses this value only to pick *which* org's `Shipit.github(organization:)` (and hence which `webhook_secret`) to check the HMAC against:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
``` [4](#0-3) 

Each org in `config/secrets.yml` has its own distinct `webhook_secret`, confirming this is a multi-tenant setup where different organizations' operators legitimately know only their own secret [5](#0-4) .

Once the HMAC passes, handlers resolve the target repository from a *different* field of the same body:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`PushHandler#process` then acts on whatever stacks resolve from `repository_name`:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [6](#0-5) 

and `StatusHandler#process` writes a commit status onto whatever `Commit` matches an attacker-supplied `sha`, independent of any org check:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [7](#0-6) 

The binding that should hold is: `organization used to select/verify the webhook secret == organization owning the repository the handler writes to`. Because `repository.owner.login` (verification key) and `repository.full_name` (write target) are two unrelated JSON leaves inside the same unauthenticated body, an attacker who legitimately knows *one* configured org's `webhook_secret` (e.g., because they administer that org's GitHub App/webhook settings themselves) can set `repository.owner.login` to their own org (so the HMAC they compute with their own secret verifies) while setting `repository.full_name` to any other org/repo known to this Shipit instance. Before: signature scope == write scope (assumed). After the attacker's crafted request: signature computed for org A, effects applied to org B's stacks — the binding is broken.

### Impact Explanation
This yields cross-repository/cross-organization writes and unauthorized deploys, matching the Critical impact bucket. Via `PushHandler`, an attacker can force `stack.sync_github(expected_head_sha: ...)` on a victim org's stack with an attacker-chosen `after` SHA, which can trigger continuous deployment of a chosen ref. Via `StatusHandler`, an attacker can forge a "success" CI status for an arbitrary commit SHA belonging to a victim org's repo, defeating CI-gating on deploys/merges. This is only possible because the security-relevant credential check (webhook signature/org) and the data-mutation target (repository/stack resolved from `full_name`) are decoupled — the same bug class as the report's `claimedAt` not being bound at the time the reward/authorization state is established.

### Likelihood Explanation
Likelihood is High in any deployment where this Shipit instance is configured for more than one GitHub organization (the documented, supported multi-tenant configuration, see `config/secrets.development.shopify.yml` and `docs/setup.md`). Any actor who legitimately controls webhook delivery for one onboarded org (i.e., knows that org's `webhook_secret`, which is routine to know/rotate for one's own org's GitHub App) can immediately exploit this against every other onboarded org's repositories, with no repository write access or privileged Shipit account required.

### Recommendation
After signature verification, re-derive the "authenticated organization" the same way for every downstream operation and enforce it: verify that `repository.owner.login` (or `organization.login`) used to select the webhook secret is the same organization portion contained in `repository.full_name`/`repository.owner.login` used by `Handler#repository_name`/`Handler#stacks` before resolving any `Repository`/`Stack`/`Commit`. Concretely, pass the verified `repository_owner` into the handler and have `Handler#stacks` reject (or scope the lookup to) repositories whose owner does not match the organization that was used to verify the signature.

### Proof of Concept
1. Shipit is configured for two organizations in `secrets.yml`: `org-a` (attacker-administered, attacker knows `org-a`'s `webhook_secret`) and `org-b` (victim, owns repo `org-b/secret-repo` with a continuous-delivery-enabled stack).
2. Attacker crafts a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/secret-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(org-a_webhook_secret, raw_body)` using the secret they legitimately hold for `org-a`.
4. POST this to the webhooks endpoint with `X-Github-Event: push`. `repository_owner` resolves to `org-a`, `verify_signature` succeeds because the HMAC matches `org-a`'s secret [3](#0-2) .
5. `PushHandler.call(params)` runs; `repository_name` resolves to `org-b/secret-repo` [8](#0-7) , and `stack.sync_github(expected_head_sha: params.after)` is invoked on `org-b`'s stack, applying the attacker-chosen SHA despite the request never being authenticated by anything `org-b` controls.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
