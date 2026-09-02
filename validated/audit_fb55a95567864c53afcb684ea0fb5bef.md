### Title
Webhook signature verification is keyed off an unverified payload field, allowing forged events for any tracked repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to use for HMAC verification based on `repository_owner`, a value read straight out of the still-unauthenticated JSON body. If any configured GitHub organization in a multi-tenant Shipit deployment has no `webhook_secret` set, `GitHubApp#verify_webhook_signature` short-circuits to `true`, meaning any payload whose `repository.owner.login`/`organization.login` matches that unsecured org bypasses signature verification entirely — while the event is still dispatched to handlers that act on whatever `repository.full_name`/`repository.owner.login` is embedded in the same forged payload. The binding broken is: the organization used to authenticate the request vs. the repository the webhook payload actually causes Shipit to write to.

### Finding Description
`verify_signature` computes the verification key before proving anything about the request is genuine: [1](#0-0) [2](#0-1) 

`repository_owner` is taken directly from `params`, i.e. the raw, unauthenticated JSON body, and is used to look up a per-organization `GitHubApp` instance via `Shipit.github(organization: repository_owner)`: [3](#0-2) 

The resulting `GitHubApp#verify_webhook_signature` intentionally treats a missing/blank `webhook_secret` as "verification not required": [4](#0-3) 

The `verified` boolean returned when `webhook_secret` is blank is `true` regardless of the actual `X-Hub-Signature` header, and `verify_signature` doesn't `return` after `head(422)` in the false branch — but more importantly, in a multi-org deployment where organization configs are keyed by `github_organizations`/`github_app_config`, each org can independently have a `webhook_secret` or not (see the setup docs showing `webhook_secret:` left blank per-environment): [5](#0-4) 

Once `verify_signature` passes (because the org picked by the untrusted `repository_owner` field has no secret configured), `WebhooksController#create` dispatches the full, forged `params` to the registered handlers for that event type, which act on whatever repository/stack the payload names — not necessarily the unsecured org: [6](#0-5) 

So the value that is authenticated (organization X, which happens to have no secret) is not the same value bound to the write (repository/stack belonging to organization Y, which does have a secret) inside the same JSON body. This is the same class of defect as the Nethermind bug: a security-relevant pointer/decision (verified-org) is advanced/trusted ahead of the data it is supposed to gate (the repository actually processed).

### Impact Explanation
An unprivileged attacker who can reach the public `/github/webhooks` endpoint can forge `push`, `status`, `check_suite`, or `membership` events for any repository/stack tracked by Shipit, as long as at least one configured GitHub organization in the deployment lacks a `webhook_secret`. This can trigger `RefreshCheckRunsJob`, commit/status updates, team/membership mutations, and other webhook-driven side effects without possessing any real GitHub credentials or the app's actual webhook secret for the targeted org — an authentication bypass for the webhook trust boundary, matching the High-severity criteria ("unauthenticated read/writes of stack state" and adjacent GitHub-authorization escalation via forged `membership`/team events).

### Likelihood Explanation
Requires the operator to run Shipit in the multi-organization mode (`github_organizations`) with at least one organization configured without a `webhook_secret` — a state the documentation explicitly shows as valid/expected (`webhook_secret:` left blank). No session, API token, or GitHub credentials are needed; only knowledge of the endpoint and of one org name in the tenant list that has no secret configured.

### Recommendation
Do not let `verify_webhook_signature` return `true` when `webhook_secret` is blank; either require every configured organization to define a `webhook_secret`, or fail closed and reject the webhook. Additionally, bind the value used to select the verification key to the same repository ultimately processed by the handler (e.g., re-validate that `repository.full_name`'s owner matches the org whose secret validated the request) rather than trusting a single unauthenticated field for both purposes.

### Proof of Concept
1. Deploy Shipit with multi-org GitHub config where org `unsecured-org` has `webhook_secret: nil` and org `victim-org` has a real secret and a tracked stack/repo `victim-org/app`.
2. POST to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "unsecured-org" }, "full_name": "victim-org/app" },
  "ref": "refs/heads/main",
  "commits": [ ... ]
}
```
(no valid `X-Hub-Signature` needed, or any arbitrary value).
3. `repository_owner` resolves to `unsecured-org`; `Shipit.github(organization: 'unsecured-org')` loads a `GitHubApp` with `webhook_secret` blank; `verify_webhook_signature` returns `true` unconditionally.
4. `WebhooksController#create` dispatches the payload — whose embedded repository info actually names `victim-org/app` — to the `push` handler, causing Shipit to process a forged commit/push event for `victim-org`'s stack despite never presenting a valid signature for `victim-org`.

### Citations

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** docs/setup.md (L100-119)
```markdown
    oauth:
      id: Iv1.bf2c2c45b449bfd9
      secret: ef694cd6e45223075d78d138ef014049052665f1
      teams:
    domain: # The domain name of your GitHub Enterprise instance, leave it empty if you use github.com
```

**`secret_key_base`** Should be generated automatically by Rails. It is used for signing session cookies etc.

**`host`** Should specify the domain of your shipit instance, e.g. `shipit.example.com`.

**`redis_url`** Should point to a working Redis database.

**`github.app_id`** The GitHub App ID, it can be found under General > About

**`github.installation_id`** The ID of your GitHub App installation, it can be found under Organization Settings > Installed GitHub Apps > Configure. Then look at the URL it should follow this pattern: `https://github.com/organizations/<you-org>/settings/installations/<app-id>`.

**`github.bot_login`** The login of the App [bot] user. Every GitHub App have an associated `[bot]` user which acts as the author of the App actions through the API, for example when an App merges a Pull Request. It should be the App "slug" with the suffix `[bot]`. For example if your app settings URL is `https://github.com/organizations/ACME/settings/apps/acme-shipit/installations`, the bot user should be `acme-shipit[bot]`. If you are unsure, you can leave it empty.

**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```
