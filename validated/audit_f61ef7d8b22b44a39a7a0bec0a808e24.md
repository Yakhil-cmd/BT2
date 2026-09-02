### Title
Webhook signature is verified against `repository.owner.login`, but the write action targets `repository.full_name` — organization-authentication/repository-write binding is broken - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate an inbound webhook against using `repository_owner`, taken from the *unverified* JSON body (`repository.owner.login`, falling back to `organization.login`). Once the signature check passes, the event handlers (e.g. `PushHandler`) determine **which `Stack`/`Repository` to act on** using a *different* field from the same unverified body: `payload.dig('repository', 'full_name')`. Nothing ties these two fields together, so an attacker who can satisfy the signature check for *any* configured organization can direct the resulting write (a forced `GithubSyncJob` sync, `mark_as_accessible!`/`mark_as_inaccessible!`, and `Commit` row creation) at a completely different organization's repository/stack.

### Finding Description
The relevant code paths:

```ruby
# app/controllers/shipit/webhooks_controller.rb
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

```ruby
# lib/shipit/github_app.rb
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

```ruby
# app/models/shipit/webhooks/handlers/handler.rb
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

```ruby
# app/models/shipit/webhooks/handlers/push_handler.rb
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [4](#0-3) 

The binding that should hold is:
`organization used to select/verify the HMAC secret (repository.owner.login) == organization that owns the repository being written to (repository.full_name's owner segment)`

Both fields come from the same untrusted, unsigned JSON body, and the body's HMAC is verified with a secret chosen *from one of the two fields* — so the signature never actually certifies which repository the payload claims to modify, only which organization key was used to look up a secret. If that organization has no `webhook_secret` configured (a supported, documented configuration — see `webhook_secret: # nil` in `docs/setup.md`, `config/secrets.development.shopify.yml`, and `test/dummy/config/secrets_double_github_app.yml`), `verify_webhook_signature` unconditionally returns `true`: [5](#0-4) [6](#0-5) 

This is exactly the "acceptable-range" analog to the Aave bug: the parameter that gates the check (`repository_owner`) and the parameter that determines the effect of the action (`repository.full_name`) are supposed to move together but are never compared, so the signature check can be satisfied for an org that has nothing to do with the repository actually being written to.

### Impact Explanation
An attacker who knows (or is granted, e.g., because they registered a Shipit-tracked org with no `webhook_secret` set — a supported configuration) any organization key configured in this Shipit instance can send a POST to `/webhooks` with `X-Github-Event: push`, setting:
- `repository.owner.login` (or `organization.login`) = the weakly-configured org, to pass `verify_signature`
- `repository.full_name` = `victim-org/victim-repo`, an entirely different, "protected" organization's repository

Because `Handler#stacks` resolves solely from `repository.full_name`, this forces `Stack#sync_github` to run against a stack the attacker never authenticated for, causing writes (new `Commit` records, `mark_as_accessible!`/`mark_as_inaccessible!` state changes, and a `CacheDeploySpecJob` enqueue) on a stack belonging to an organization whose signature was never validated. This is a cross-organization write triggered without ever satisfying the security boundary that is supposed to scope the action to the authenticated organization's own repositories.

### Likelihood Explanation
Likelihood is limited by needing at least one organization configured on the instance with no `webhook_secret` (or a leaked/guessable one) — a state explicitly shown as valid/supported in this codebase's own example configs and setup docs, making it plausible in real multi-tenant deployments where operators onboard a low-risk org without bothering to set a webhook secret, unaware that doing so also weakens every *other* configured org's repositories against forged sync triggers.

### Recommendation
Do not select the signature-verification organization from a body field disjoint from the one used to resolve the target repository/stack. Verify the signature using the secret associated with the same `repository.full_name`'s owner (or `Repository` record) that `Handler#stacks` will act on, and reject the webhook if the two disagree. Also consider making `webhook_secret` mandatory for every configured GitHub organization instead of treating it as optional.

### Proof of Concept
1. Configure (or find already configured) two orgs in `config/secrets.yml`: `weak-org` (no `webhook_secret`) and `victim-org` (has a stack `victim-org/victim-repo` tracked in Shipit).
2. Send:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything

{
  "ref": "refs/heads/main",
  "after": "<current head sha of victim-org/victim-repo>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "weak-org" }
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: "weak-org")` → `verify_webhook_signature` returns `true` immediately because `weak-org` has no `webhook_secret` (`lib/shipit/github_app.rb:76-77`), regardless of the bogus `X-Hub-Signature`.
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), and calls `stack.sync_github(...)`, enqueuing `GithubSyncJob` for `victim-org/victim-repo`, entirely bypassing any need to know `victim-org`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** docs/setup.md (L182-209)
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
