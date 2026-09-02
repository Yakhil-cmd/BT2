### Title
Webhook consumer authenticates by `repository.owner.login`/`organization.login` but acts on the unverified `repository.full_name` field, allowing cross-organization webhook forgery when any onboarded GitHub App has no `webhook_secret` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to verify a webhook against using `repository.owner.login` (falling back to `organization.login`), then HMAC-verifies the raw body against that org's secret. [1](#0-0) [2](#0-1)  However, the actual event handlers (`PushHandler`, `StatusHandler`, etc.) resolve which `Stack`/`Repository` to act on using a *different* JSON field: `repository.full_name`, via `Handler#repository_name`/`#stacks`. [3](#0-2)  No code anywhere checks that `repository.full_name`'s owner matches the org (`repository.owner.login`) that was used for signature verification. Combined with `GithubApp#verify_webhook_signature` returning `true` unconditionally when `webhook_secret` is blank (an explicitly documented "optional" setting), [4](#0-3)  this breaks the equality **Org(signature-verified) == Org(repository acted upon)**.

### Finding Description
The verification binding is:
```
github_app = Shipit.github(organization: repository_owner)   # keyed by repository.owner.login / organization.login
verified = github_app.verify_webhook_signature(X-Hub-Signature, raw_post)
``` [1](#0-0) 

```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 

But the write-path binding used by every default handler is:
```
def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

`PushHandler#process` uses this to find stacks and immediately enqueue a sync with an attacker-supplied SHA:
```
def process
  stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [6](#0-5) 

Because `repository_owner` (used only to pick the verification secret) and `repository.full_name` (used to pick the actual DB `Repository`/`Stack`) are two independent, attacker-controlled JSON keys in the same unauthenticated POST body, and because docs explicitly describe `webhook_secret` as "optional", [7](#0-6)  any deployment (single- or multi-org, per the "Using Multiple Github Applications" config format) [8](#0-7)  that has even one organization configured without a `webhook_secret` allows an unauthenticated attacker to:
1. Set `repository.owner.login` (or `organization.login`) to that unsecured org — `verify_signature` will call `verify_webhook_signature` which returns `true` unconditionally regardless of the `X-Hub-Signature` header.
2. Set `repository.full_name` to any *other* repository/stack registered in the same Shipit instance (e.g. a securely configured org) and `ref`/`after` to an attacker-chosen commit SHA.
3. The `push` handler will look up that victim `Stack` purely by `full_name` and enqueue `stack.sync_github(expected_head_sha: <attacker sha>)`, with no re-validation that the "authenticated" organization actually owns that repository.

### Impact Explanation
If the affected stack has continuous deployment enabled, this can force Shipit to sync/deploy an attacker-chosen commit SHA to a victim repository's stack that the attacker has no legitimate access to — this is an unauthorized deploy triggered purely by an unauthenticated HTTP POST to `/webhooks`, meeting the "Critical — unauthorized deploy" bar. Even without continuous deployment, it corrupts commit/CI state (`status`/`check_suite`/`membership` handlers have analogous `full_name`/`organization` decoupling), enabling griefing and false CI status injection across arbitrary registered repositories, independent of which org's credentials were actually verified.

### Likelihood Explanation
Exploitability hinges entirely on at least one onboarded GitHub App/org lacking a `webhook_secret`, which the setup docs mark as optional and is a plausible real-world misconfiguration (e.g. staging/dev orgs, or an admin who skipped the "optional" field) in a multi-tenant Shipit install. Once that condition holds, the attack requires no credentials, no signature computation, and no repository write access — a single crafted JSON POST suffices. This matches the report's core bug class ("payload field acted upon but never covered by the verified signature").

### Recommendation
- Never allow `verify_webhook_signature` to silently return `true` for a blank secret in production; require a `webhook_secret` for every configured organization, or reject webhooks for organizations without one.
- Bind verification and consumption to the same field: after signature verification, assert that `repository.full_name.split('/').first` (or `repository.owner.login`) equals the org whose secret verified the payload, before resolving `stacks`/`Repository.from_github_repo_name`.
- Consider deriving `repository_owner` and `repository_name` from a single canonical source and validating internal consistency of the payload before dispatch to handlers.

### Proof of Concept
Given a multi-org `secrets.yml` where org `unsecured-org` has no `webhook_secret` set and org `victim-org` (with a properly configured stack `victim-org/prod-app`) does:

```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=0000000000000000000000000000000000000000
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "unsecured-org" },
    "full_name": "victim-org/prod-app"
  }
}
```
`verify_signature` resolves `Shipit.github(organization: "unsecured-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the bogus `X-Hub-Signature`. [9](#0-8)  `PushHandler#process` then resolves stacks for `victim-org/prod-app` (via `repository.full_name`) and enqueues `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for the victim's stack. [6](#0-5)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
