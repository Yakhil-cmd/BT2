### Title
Webhook signature verification keys off an attacker-controlled organization field that is not bound to the repository the event is applied to - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The bug class in the report is a binding mismatch: the field used to compute/verify a "trust" property (D / virtual_price via `_balances()`) is not the same field the privileged action (`remove_liquidity_one_coin`/`exchange_received`) actually operates on. In `WebhooksController`, the same mismatch exists between the field used to select **which GitHub App secret to verify the HMAC signature against** and the field the event handlers actually use to decide **which repository/stack the event is applied to**.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/organization used to check the webhook HMAC purely from attacker-supplied JSON, before the signature has been validated: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the unauthenticated `params` (`repository.owner.login` or `organization.login`), and is used to call `Shipit.github(organization: repository_owner)`, which looks up that org's configured `webhook_secret` in `GithubApp`: [3](#0-2) [4](#0-3) 

Critically, `verify_webhook_signature` **trivially returns `true` if no `webhook_secret` is configured for that organization** (`return true unless webhook_secret`). In a multi-org deployment (supported, as shown by the fixture configuring two orgs where one has `webhook_secret: # nil`), an attacker can craft a payload whose `repository.owner.login`/`organization.login` claims the unsecured/misconfigured org, causing signature verification to pass unconditionally — while the event body's actual `repository.full_name` (used later by the event handler, e.g. `push_handler.rb`, `status_handler.rb`, `check_suite_handler.rb`) can reference a *different*, properly-secured repository/stack that the request has no legitimate authorization to mutate.

The equality that should hold but doesn't: `organization used to verify signature == organization owning the repository the event handler writes to`. The controller enforces neither that these two are the same GitHub App/org, nor that the resolved repository actually belongs to the org whose secret validated the request.

### Impact Explanation
If any configured `GithubApp` organization lacks a `webhook_secret` (a supported, non-error configuration per `test/dummy/config/secrets_double_github_app.yml`), an attacker who knows this can forge webhook payloads (push, status, check_suite, membership, pull_request, merge events) targeting *any* repository/stack tracked by Shipit, not just the unsecured org's own repos — because handlers resolve the affected `Stack`/`Repository` by the payload's `repository.full_name`, independent of which org's secret gated the request. Depending on which handler is targeted, this can drive unauthorized commit-status injection, spurious CI-check state, membership/team churn, or interference with the merge queue and deploy triggers, for repositories under an org that *does* enforce a webhook secret — an authentication bypass into privileged webhook-driven mutations of stack state.

### Likelihood Explanation
Requires a Shipit installation configured with more than one GitHub App/organization where at least one organization has no `webhook_secret` set (this is an explicitly supported and tested configuration shape in this repo, not a hypothetical). No credentials, tokens, or repository access are needed — only knowledge (or discovery, e.g., via trial payloads that get accepted) of which configured org has no secret. This is a pure unauthenticated-attacker path through `WebhooksController#create`.

### Recommendation
Verify the webhook signature using the secret belonging to the organization/app that actually owns the repository referenced by the payload's content that the handler will act on, and reject events where the two disagree. Additionally, do not allow `verify_webhook_signature` to silently return `true` for an organization with no configured secret when the engine is configured with multiple GitHub Apps — require an explicit secret for every configured org, or bind the org used for verification to the resolved `Stack`/`Repository` before dispatching handlers.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `OrgSecured` (has `webhook_secret` set) and `OrgOpen` (no `webhook_secret`), matching the pattern in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker POSTs to `/github/webhooks` a `push` (or `status`/`check_suite`) event with:
   - `X-Github-Event: push`
   - Body: `repository.owner.login = "OrgOpen"` (or `organization.login = "OrgOpen"`) but `repository.full_name = "OrgSecured/some-tracked-repo"`
   - No valid `X-Hub-Signature` (or any arbitrary value).
3. `verify_signature` calls `Shipit.github(organization: "OrgOpen")`, whose `verify_webhook_signature` returns `true` immediately because `OrgOpen`'s `webhook_secret` is `nil`.
4. `create` proceeds to `Shipit::Webhooks.for_event('push').each { |handler| handler.call(params) }`, and `push_handler.rb` resolves the stack/repository via `repository.full_name`, i.e. `OrgSecured/some-tracked-repo`, enqueuing a `GithubSyncJob` (or equivalent) for that repository despite the forged/absent signature never being checked against `OrgSecured`'s actual `webhook_secret`.

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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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
