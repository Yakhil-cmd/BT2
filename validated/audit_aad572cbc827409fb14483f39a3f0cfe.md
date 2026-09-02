### Title
Webhook signature verification is silently skipped when `webhook_secret` is blank, allowing unauthenticated forgery of commit statuses across every stack in the instance - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`GitHubApp#verify_webhook_signature` treats the "no secret configured" case as an automatic pass, exactly like the reported `merkleProof.length == 0` bug: an edge/degenerate input (an empty/blank secret) is accepted as "verified" instead of being rejected. Because Shipit's own generated production template ships with `webhook_secret:` left blank, and the docs describe the webhook secret as "(optional)", this degenerate path is realistically reachable in real deployments. Once verification is bypassed, the webhook payload is processed by handlers such as `StatusHandler`, which write commit status rows by matching `sha` **globally across the whole database**, with no check that the commit belongs to the repository/organization that supposedly "authenticated" the webhook.

### Finding Description
`GitHubApp#verify_webhook_signature` is defined as: [1](#0-0) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

If `webhook_secret` is blank for the organization resolved from the payload, verification is **skipped entirely** and the request is treated as authentic - directly analogous to accepting a zero-length Merkle proof as valid. This is not a theoretical corner case: the engine's own installer template leaves the field empty by default: [2](#0-1) 
and the setup docs describe it as optional: [3](#0-2) 

`WebhooksController#verify_signature` selects which `GitHubApp`/secret to check against using an attacker-controlled payload field, `repository_owner`: [4](#0-3) 

So the "authenticated organization" binding is: `github_app selected via payload.repository.owner.login (or organization.login)` == `organization whose secret was checked`. Nothing binds that organization to the actual repository/commit that downstream handlers mutate.

Once past `verify_signature`, `WebhooksController#create` dispatches the raw JSON body to registered handlers: [5](#0-4) 

`StatusHandler#process` writes a commit status by looking up commits **only by `sha`**, with no scoping to the repository/organization that was supposedly authenticated: [6](#0-5) 

`Commit.where(sha: params.sha)` is unscoped across the entire `commits` table, i.e. across every stack/repository/organization tracked by this Shipit instance, not just the one identified by `repository_owner`. This breaks exactly the binding class called out in scope: *"an organization that authenticated versus the repository that is written."*

### Impact Explanation
An unauthenticated, unprivileged network attacker (no Shipit session, no `ApiClient` token, no knowledge of `webhook_secret`, no GitHub App private key, no repository write access) can:
1. POST directly to the public `/webhooks` endpoint with `X-Github-Event: status`.
2. Set `repository.owner.login` (or `organization.login`) to any organization configured in `Shipit.github_organizations` whose `webhook_secret` is blank (the shipped default).
3. Supply an arbitrary `sha` matching any commit tracked by *any* stack in the instance (commit SHAs are public GitHub data, easily discoverable) and `state: "success"`.

Because `StatusHandler` matches commits globally, the attacker can inject a fabricated "success" commit status for a commit belonging to a completely different repository/organization than the one used to bypass verification. If that status context is one referenced by a stack's `ci.require`/`ci.blocking` configuration, this can make an otherwise non-deployable commit appear deployable, directly enabling an **unauthorized deploy** - one of the explicitly accepted Critical impacts.

### Likelihood Explanation
High, given: (a) the vulnerable "return true unless webhook_secret" logic is present in the shipped code, (b) the engine's own installer template and documentation actively encourage leaving the webhook secret blank ("optional"), and (c) the `/webhooks` endpoint requires no authentication whatsoever to reach - it is the public entry point by design.

### Recommendation
- Change `verify_webhook_signature` to fail closed (reject) when `webhook_secret` is blank, rather than treating it as automatically verified, mirroring the recommended fix of requiring a non-empty/valid proof rather than accepting a degenerate empty one.
- Scope all webhook handlers (especially `StatusHandler`) to the repository/organization actually identified and authenticated in the payload (e.g. join through `Repository`/`Stack` matching `repository.full_name` and the verified organization) instead of matching commits globally by `sha` alone.
- Make `webhook_secret` a mandatory, validated configuration value rather than documented as optional.

### Proof of Concept
1. Deploy Shipit using the stock `template.rb` config (webhook_secret left blank) or configure any organization in `Shipit.github_organizations` without a `webhook_secret`.
2. Identify a target commit SHA belonging to some stack/repository tracked by the instance (public GitHub data).
3. Send, without any authentication:
```
POST /webhooks
X-Github-Event: status
Content-Type: application/json

{
  "sha": "<target commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {"owner": {"login": "<org-with-blank-secret>"}, "full_name": "<org-with-blank-secret>/anything"}
}
```
4. `verify_signature` resolves `Shipit.github(organization: "org-with-blank-secret")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` without checking `X-Hub-Signature` at all.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)` and creates a status record for the target commit regardless of which repository/organization it actually belongs to, potentially satisfying `ci.require` and enabling deployment of that commit.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** template.rb (L102-107)
```ruby
      github:
        domain: # defaults to github.com
        app_id: <%= ENV['GITHUB_APP_ID'] %>
        installation_id: <%= ENV['GITHUB_INSTALLATION_ID'] %>
        webhook_secret:
        private_key:
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
