### Title
Webhook signature bypass allows cross-organization/repository event injection - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC signature against using `repository_owner`, a value taken directly from the untrusted JSON body (`repository.owner.login`, falling back to `organization.login`). The downstream event handlers, however, resolve the actual repository/stack to act on using a *different* field from the same body: `repository.full_name`. These two fields are never cross-checked against each other, breaking the binding "organization that authenticated the webhook == repository whose events are written".

### Finding Description
`verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [1](#0-0) 
where `repository_owner` is read straight from the attacker-controlled payload:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`GitHubApp#verify_webhook_signature` explicitly bypasses verification if that organization has no configured `webhook_secret`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

The setup docs explicitly describe the webhook secret as **optional**, and the multi-organization config format documented in `docs/setup.md` allows several orgs to be configured independently, each with its own (possibly blank) `webhook_secret`. [4](#0-3) [5](#0-4) 

Meanwhile, `Handler#stacks`/`Handler#repository_name` resolve the actual repository acted upon using an entirely separate JSON field:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

Because `repository_owner` (used to select which secret to check) and `repository.full_name` (used to select which repository's stacks are processed) are independent fields inside the same raw body, an attacker can satisfy signature verification for one org while directing the actual event processing at a completely different, unrelated repository/stack that has no such weak configuration. This directly matches the report's bug class: a field that is acted upon but not actually covered by the binding that is meant to protect it (here, the "verified organization" is decoupled from the "written repository").

### Impact Explanation
If any organization configured in a multi-org Shipit deployment has no `webhook_secret` set (an explicitly supported and documented configuration), an unauthenticated attacker can:
1. Send a POST to `/webhooks` with `X-Github-Event: push` (or `membership`, `status`, `check_suite`, etc.).
2. Set `repository.owner.login` (or `organization.login`) to the name of the weakly-configured org, causing `verify_signature` to short-circuit `true` without any valid HMAC.
3. Set `repository.full_name` to any other repository/stack actually tracked by this Shipit instance.

This lets the attacker inject arbitrary, unsigned webhook events (push, membership, status, check_suite, pull_request, etc.) against any stack in the whole Shipit installation — not just the weakly-configured org. Depending on which handler is targeted this can trigger `GithubSyncJob` runs (potentially advancing/triggering continuous-delivery deploys) via `PushHandler#process` -> `stack.sync_github`, or manipulate `Membership`/`Team` records via the membership handler, which underpin the `current_user.authorized?` check gating access to the entire application (`app/controllers/concerns/shipit/authentication.rb`). This crosses the "authorization escalation into `Shipit.github_teams`" / "unauthorized deploy" impact bar.

### Likelihood Explanation
Requires only that the operator has configured at least one organization without a `webhook_secret` in a multi-org setup — an officially supported and documented configuration (marked "optional" in `docs/setup.md` and shown with blank `webhook_secret` fields in `config/secrets.development.shopify.yml`). No credentials, tokens, or prior access are needed; the request is a plain unauthenticated HTTP POST to a public endpoint.

### Recommendation
Bind repository resolution to the same authenticated identity used for signature verification: after `verify_signature` succeeds, assert that `repository.full_name`'s owner matches `repository_owner` (the organization whose secret validated the request), and reject the webhook otherwise. Alternatively, disallow `webhook_secret` from being blank/optional when multiple organizations are configured, or verify the signature against the specific `Repository` record's owning organization rather than a value taken directly from the untrusted payload.

### Proof of Concept
Given a `secrets.yml` with two orgs, e.g.:
```yaml
github:
  weakorg:
    app_id: ...
    installation_id: ...
    webhook_secret: # blank/nil
  victimorg:
    app_id: ...
    installation_id: ...
    webhook_secret: some-secret
```
An attacker, with no credentials, sends:
```http
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything-or-omitted

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "weakorg" },
    "full_name": "victimorg/protected-repo"
  }
}
```
`verify_signature` calls `Shipit.github(organization: "weakorg")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally regardless of the (bogus) `X-Hub-Signature` header. `PushHandler` then resolves the stack via `payload.dig('repository', 'full_name')` = `"victimorg/protected-repo"`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the real, unrelated `victimorg` stack — an unauthenticated actor influencing sync/deploy behaviour for a repository whose organization has a real webhook secret configured.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
