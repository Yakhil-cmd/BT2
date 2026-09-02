## Analysis

Confirmed the exploit chain: `Repository.from_github_repo_name(repository_name)` in `Handler#stacks` resolves the target `Stack`/`Repository` from `payload.dig('repository', 'full_name')` [1](#0-0) , which is the same JSON body used by `WebhooksController#repository_owner` to select which GitHub App config (and thus which `webhook_secret`) is used to verify the signature [2](#0-1) [3](#0-2) . Critically, `verify_webhook_signature` unconditionally returns `true` when `webhook_secret` is blank for that resolved organization [4](#0-3) , and the setup docs/config show `webhook_secret` is legitimately expected to be nil for some configured organizations in multi-org deployments [5](#0-4) .

### Title
Webhook signature verification is keyed by an attacker-controlled `repository.owner.login` field, allowing forged events when any configured organization lacks a `webhook_secret` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App configuration used to verify `X-Hub-Signature` based on `repository_owner`, a value extracted directly from the untrusted JSON body rather than any authenticated source. If any organization in `secrets.yml` is configured without a `webhook_secret` (an explicitly supported configuration, shown as `webhook_secret: # nil` in `config/secrets.development.shopify.yml`), `GitHubApp#verify_webhook_signature` returns `true` unconditionally for that organization. An attacker can therefore submit a forged webhook payload whose `repository.owner.login`/`organization.login` names that unprotected organization, bypassing signature verification entirely, while the same payload field also determines which `Repository`/`Stack` the event handler acts on via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`.

### Finding Description
- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (attacker-controlled body) and calls `Shipit.github(organization: repository_owner)` to fetch the app config used to verify the signature [2](#0-1) .
- `GitHubApp#verify_webhook_signature` explicitly bypasses HMAC verification (`return true unless webhook_secret`) when the resolved organization has no secret configured [4](#0-3) .
- The equality that should hold — "the organization whose secret authenticated the request" == "the organization/repository the payload's handler actually writes to" — is broken because both sides are derived from the same unauthenticated field, and one path (`webhook_secret` blank) removes authentication altogether while the write path (`Handler#stacks`, using `payload.dig('repository', 'full_name')`) still executes normally [1](#0-0) .
- Any org lacking `webhook_secret` (an intentionally supported, documented state) turns the check into a no-op for events claiming that org, and `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` in `WebhooksController#create` then processes the forged payload with full trust [6](#0-5) .

### Impact Explanation
For any organization without a configured `webhook_secret`, an unauthenticated attacker can submit arbitrary forged webhook events (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.) for repositories under that organization. This can trigger `PushHandler#process` to call `stack.sync_github(expected_head_sha: ...)` [7](#0-6) , create/delete `Team`/`Membership`/`User` records via the membership handler, or inject forged commit statuses — all without any credential. This is a repository-write/authentication-bypass class impact, contingent entirely on the deployment having at least one organization configured without a webhook secret, which the engine's own reference configuration treats as a normal, expected setup.

### Likelihood Explanation
Likelihood is conditioned on operator configuration: it requires at least one `github.<org>.webhook_secret` entry to be blank/nil in `secrets.yml`, a state explicitly modeled in the shipped `config/secrets.development.shopify.yml` template and permitted by `GitHubApp#verify_webhook_signature`'s design (`return true unless webhook_secret`). Any multi-organization Shipit deployment that has not set a webhook secret for every configured org is exposed with no additional prerequisites — the attacker needs no token, no session, and no prior access.

### Recommendation
Do not allow signature verification to succeed when `webhook_secret` is unset for a real (non-legacy single-app) organization; either require `webhook_secret` for all configured GitHub App organizations, or fail closed (`head(422)`) instead of returning `true` when no secret is configured in multi-org mode. Additionally, do not use unauthenticated payload fields to select the verification key at all — verification should not be self-referential to attacker input.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`: `protected-org` (with `webhook_secret` set) and `open-org` (with `webhook_secret` left blank, as shown in `config/secrets.development.shopify.yml`).
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature`, body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "open-org/some-repo",
    "owner": { "login": "open-org" }
  }
}
```
3. `repository_owner` resolves to `open-org`; `Shipit.github(organization: 'open-org')` has `webhook_secret` blank, so `verify_webhook_signature` returns `true` and the request passes `before_action :verify_signature`.
4. `PushHandler#process` runs against any `Stack` whose `Repository.from_github_repo_name('open-org/some-repo')` matches, invoking `stack.sync_github(expected_head_sha: ...)` with fully attacker-controlled data, despite no valid GitHub signature ever being presented.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
