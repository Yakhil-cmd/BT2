## Finding [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Title
Cross-organization webhook signature verification bypass via query-string/body parameter mismatch — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify the webhook HMAC against by calling `repository_owner`, which reads `params.dig('repository', 'owner', 'login')`. This `params` is Rails' merged `ActionController::Parameters` (query string GET params merged over/overriding JSON body POST params), **not** the actual webhook JSON body. The actual event body used to determine which stack/repository gets acted upon is parsed independently and freshly inside `create` via `params = JSON.parse(request.raw_post)`, a local variable scoped only to that method. The org used for the HMAC key lookup and the repository that is actually written to by the handler can therefore be two entirely different organizations.

### Finding Description
The binding that should hold is: **organization whose webhook secret authenticated the request == organization/repository that the handler subsequently acts on**. This binding is broken because two different sources of "the payload" are used before and after signature verification:

1. `verify_signature` (a `before_action`) calls `repository_owner`, which reads Rails' `params` — this reflects the request's query string merged with any Rails-auto-parsed body, with **query string values taking precedence**. `Shipit.github(organization: repository_owner)` is then used to pick which org's `webhook_secret` verifies `request.raw_post`'s HMAC. [5](#0-4) 
2. `create` independently re-parses the *actual* raw body (`JSON.parse(request.raw_post)`) and dispatches it to `Shipit::Webhooks.for_event(event)` handlers, which act on whatever `repository.full_name` / `repository.owner.login` is in that real JSON body. [6](#0-5) 

An attacker can send `POST /webhooks?repository[owner][login]=<org-with-no-or-known-secret>&X-Github-Event=push` with a JSON body whose `repository.owner.login`/`full_name` targets a *different*, victim organization's tracked stack. Signature verification is performed using the attacker-chosen org's secret (selected via the query string), while the actually-processed payload belongs to the victim org.

This is compounded by `GitHubApp#verify_webhook_signature`, which treats an unset `webhook_secret` as "always verified": [4](#0-3) 
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```
Shipit's own setup documentation states the webhook secret is optional per app/org: [7](#0-6) 

So in any multi-organization Shipit deployment where at least one configured GitHub App/org has no `webhook_secret` set (an explicitly supported, documented configuration), an unauthenticated attacker can pick that org via the query string to trivially satisfy `verify_signature`, then forge a body targeting any other organization's repository/stack that Shipit tracks — with no secret knowledge required at all.

### Impact Explanation
This is a signature-verification bypass that lets an unauthenticated, unprivileged attacker forge GitHub webhook events (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.) against any repository/stack managed by the Shipit instance:
- Forged `push` events trigger `GithubSyncJob`/`stack.sync_github`, letting an attacker manipulate which commits Shipit believes exist on the deploy branch.
- Forged `status` events create/alter commit statuses, which can satisfy `ci.require`/`allow_failures` checks gating deploys and merge-queue merges — enabling an **unauthorized deploy** (or an unauthorized merge via the merge-queue's CI gating), matching the Critical-impact category ("unauthorized deploy, rollback or merge").
- Forged `membership`/`check_suite` events corrupt team/user state or trigger check-run refreshes for arbitrary repositories.

### Likelihood Explanation
No credentials, tokens, or prior access are required beyond the ability to send an HTTP POST to the public `/webhooks` endpoint (the standard GitHub webhook receiver, unauthenticated by design). The only precondition is that at least one org configured in `Shipit.github` secrets omits `webhook_secret` — an officially supported/documented configuration, or that the attacker separately knows/controls a secret for any one configured org (e.g., their own test org's GitHub App) to compute a valid HMAC to satisfy `verify_signature` while targeting a victim org's repository in the body.

### Recommendation
- Compute `repository_owner` (and any other value used to pick the verifying organization) from the same parsed body used later for processing — parse `request.raw_post` once (e.g., store it in `before_action` and reuse in `create`), never from Rails' `params`.
- Do not allow query-string parameters to influence which organization's secret is used for verification.
- Consider treating a blank/missing `webhook_secret` as "reject" rather than "always verified", or at minimum verify that the JSON-body-derived organization matches the query-derived value before trusting either.

### Proof of Concept
1. Configure two orgs in `Shipit.github` secrets: `attacker-org` (no `webhook_secret` configured — a documented optional field) and `victim-org` (tracked stacks exist for `victim-org/some-repo`).
2. Attacker sends:
```
POST /webhooks?repository[owner][login]=attacker-org
X-Github-Event: push
Content-Type: application/json

{"ref":"refs/heads/main","after":"<attacker-chosen-sha>","repository":{"owner":{"login":"victim-org"},"full_name":"victim-org/some-repo"}}
```
No `X-Hub-Signature` header is required, or any arbitrary value works.
3. `verify_signature` calls `repository_owner`, which — via Rails' query-string-precedence `params` — resolves to `attacker-org`. `Shipit.github(organization: 'attacker-org').verify_webhook_signature(...)` returns `true` immediately because `attacker-org` has no `webhook_secret`.
4. `create` re-parses the real JSON body and dispatches the `push` event to `Shipit::Webhooks::Handlers::PushHandler`, which resolves `stacks` from `repository.full_name` = `victim-org/some-repo` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` — a forged push event fully processed for the victim's stack, with signature verification never actually checked against `victim-org`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-16)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```
