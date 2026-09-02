### Title
Webhook signature verification is bound to an attacker-chosen organization, not the repository the payload actually mutates - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate a webhook against using an organization name taken directly from the untrusted, unauthenticated JSON payload (`repository.owner.login` or `organization.login`), but the event handlers that subsequently mutate state resolve the target `Repository`/`Stack` from a *different* field of that same payload (`repository.full_name`), with no check that the two are consistent or belong to the same authenticated GitHub App installation.

### Finding Description
The webhook endpoint is unauthenticated by design and relies entirely on HMAC signature verification to establish trust: [1](#0-0) [2](#0-1) 

The organization used to select the verifying GitHub App config is taken from the raw, unverified request body itself (`repository.owner.login`), before the signature over that same body has been checked. `GitHubApp#verify_webhook_signature` is fail-open when no `webhook_secret` is configured for that organization: [3](#0-2) 

Meanwhile, the actual event processing resolves the repository/stack to mutate using a *different* payload field, `repository.full_name`, via `Handler#repository_name`/`#stacks`: [4](#0-3) 

and `PushHandler#process` uses that to enqueue a sync using an attacker-supplied `after` sha: [5](#0-4) 

Because the entire raw POST body is attacker-controlled (the endpoint is unauthenticated until signature verification succeeds), and because `owner.login` (used for auth) and `full_name` (used for the write target) are two independently attacker-settable strings within the same JSON body, nothing in the code enforces the equality: `organization whose webhook_secret authenticated the request == owner of the repository being acted upon`. Configuration docs and generators explicitly show `webhook_secret` as optional/blank per organization, and Shipit supports multiple configured GitHub organizations simultaneously: [6](#0-5) [7](#0-6) 

### Impact Explanation
In a multi-organization Shipit deployment where at least one configured organization has no `webhook_secret` set (a supported, documented configuration state, not a code error), `verify_webhook_signature` returns `true` unconditionally for any payload claiming `repository.owner.login` (or `organization.login`) equal to that org — with zero knowledge of any secret. An attacker can then set `repository.full_name` in the same forged payload to point at a *different*, properly-secured organization's tracked repository/stack. The `push` handler will enqueue `GithubSyncJob` with an attacker-chosen `expected_head_sha` for that victim stack, and other handlers (`status`, `check_suite`, etc.) similarly act on state keyed off `repository.full_name`/`organization.login` fields never covered by the org used for auth. If continuous deployment is enabled on the targeted stack, this lets an unprivileged, credential-less attacker force an out-of-band sync/deploy trigger against a stack belonging to an organization whose webhook secret was never presented or known to the attacker — a direct violation of the "organization that authenticated versus the repository that is written" binding called out as an accepted analog class.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment, and (2) at least one configured organization without a `webhook_secret` (an explicitly supported and documented state, and the default in generated/development secrets templates) while at least one other organization with tracked stacks has a "properly" configured secret. This is a plausible, realistic operational configuration (e.g., staging/demo org added without a secret) rather than a purely theoretical setup, but it is a precondition outside the attacker's control, which limits likelihood relative to a universally-exploitable bug.

### Recommendation
- Verify the webhook signature against the secret of the organization that actually owns the resource being mutated (`repository.full_name`'s owner segment or the `Stack`'s associated `Repository#owner`), not an independently-controlled field of the same untrusted payload.
- Do not treat a missing `webhook_secret` as "signature verification passes" (`return true unless webhook_secret`); instead reject or require explicit opt-in for unauthenticated organizations, and never let such an org's identity be used to validate events destined for a different, secured organization's repositories.
- Cross-check that `repository.owner.login` and `repository.full_name`'s owner segment match before dispatching to handlers.

### Proof of Concept
Precondition: Shipit configured with two orgs, `no-secret-org` (no `webhook_secret`) and `victim-org` (has `webhook_secret`, has a tracked `Stack` for `victim-org/app` on branch `main` with continuous deployment enabled).

```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha, e.g. current real HEAD to force premature deploy>",
  "repository": {
    "owner": { "login": "no-secret-org" },
    "full_name": "victim-org/app"
  }
}
```
No `X-Hub-Signature` header (or any garbage value) is required: `verify_signature` resolves `Shipit.github(organization: "no-secret-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` immediately [3](#0-2) . `WebhooksController#create` then dispatches the full payload to `PushHandler`, which resolves the target using `repository.full_name` = `"victim-org/app"` [4](#0-3)  and enqueues a sync/deploy trigger for that victim stack [5](#0-4) , despite the attacker never possessing `victim-org`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** template.rb (L97-113)
```ruby
    production:
      app_name: My Shipit
      secret_key_base: <%= ENV['SECRET_KEY_BASE'] %>
      host: <%= ENV['SHIPIT_HOST'] %>
      redis_url: <%= ENV['REDIS_URL'] %>
      github:
        domain: # defaults to github.com
        app_id: <%= ENV['GITHUB_APP_ID'] %>
        installation_id: <%= ENV['GITHUB_INSTALLATION_ID'] %>
        webhook_secret:
        private_key:
        oauth:
          id: <%= ENV['GITHUB_OAUTH_ID'] %>
          secret: <%= ENV['GITHUB_OAUTH_SECRET'] %>
          # teams: MyOrg/developers # Enable this setting to restrict access to only the member of a team
      env:
        # SSH_AUTH_SOCK: /foo/bar # You can set environment variable that will be present during deploys.
```
