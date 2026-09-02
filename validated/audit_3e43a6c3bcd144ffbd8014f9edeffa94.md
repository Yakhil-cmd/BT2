### Title
Webhook signature verified against `repository.owner.login`/`organization.login`, but event handlers act on the independent `repository.full_name` field — cross-organization webhook forgery ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports multi-tenant GitHub configuration, where each organization has its own `webhook_secret` looked up via `Shipit.github(organization: ...)` [1](#0-0) . `WebhooksController#verify_signature` picks *which* organization's secret to validate the HMAC against using `repository_owner`, which reads `repository.owner.login` (falling back to `organization.login`) from the untrusted JSON payload [2](#0-1) . Once the signature check passes, the `create` action dispatches the *entire* raw payload to `Shipit::Webhooks.for_event(event)` handlers [3](#0-2) . Those handlers determine which `Repository`/`Stack` to mutate using a *different* field of the same payload: `payload.dig('repository', 'full_name')`, via the shared `Handler#repository_name` helper [4](#0-3) . No code path cross-checks that `repository.owner.login` (used to select the signing secret) matches the owner segment of `repository.full_name` (used to select the actual repository to act on).

### Finding Description
The equality that should hold is:

`organization whose webhook secret authenticated the request == organization that owns the repository the handler mutates`

In practice, this reduces to `repository.owner.login (or organization.login) == owner segment of repository.full_name`, but the code never enforces it — the two values come from independently attacker-controlled fields inside the same JSON body.

Any organization onboarded into Shipit with its own GitHub App/webhook configuration has, by design, legitimate possession of its own `webhook_secret` [1](#0-0) . Such an org admin (an "unprivileged attacker" relative to any *other* org tracked by the same Shipit instance) can HMAC-sign an arbitrary payload with their own valid secret, set `repository.owner.login` (or `organization.login`) to their own org so `verify_signature` resolves and validates against their own secret [5](#0-4) , while setting `repository.full_name` to `victim-org/victim-repo` — a repository that belongs to a completely different organization tracked by the same Shipit instance.

Because `Handler#repository_name` simply trusts `payload.dig('repository', 'full_name')` to resolve `Repository.from_github_repo_name` and its `stacks` [6](#0-5) , e.g. `PushHandler#process` will look up and mutate stacks under `victim-org/victim-repo`, triggering `stack.sync_github(expected_head_sha: params.after)` [7](#0-6)  — entirely for a repository the forger neither owns nor whose secret they know.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust boundary explicitly called out as an in-scope analog. An attacker who legitimately administers Org A's GitHub App/webhook config in a shared Shipit instance can forge webhook events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) that are cryptographically validated using Org A's secret but whose payload content targets Org B's repository/stack. Depending on which handler is invoked, this can force out-of-band syncs, spoof commit/check statuses consumed by the merge queue (`MergeStatusController`), or otherwise manipulate state belonging to a repository the attacker has no legitimate write access to — a cross-repository/cross-tenant write triggered purely by forging a signed webhook body, without ever needing a Shipit session, an `ApiClient` token, or GitHub write access to the victim repository.

### Likelihood Explanation
Exploitability requires only that the attacker controls one legitimately configured organization/webhook secret within a multi-tenant Shipit deployment (which `Shipit.github(organization:)`/`GithubOrganizationUnknown` explicitly supports) [8](#0-7) . No privileged Shipit credentials, GitHub App private key, or victim-repo access are needed — only crafting a raw HTTP POST with a valid HMAC for their own org's secret and a `repository.full_name` pointing elsewhere. This is a straightforward, config/code-level gap rather than a theoretical or best-practice issue.

### Recommendation
In `WebhooksController#verify_signature`, after determining `repository_owner` and validating the signature, additionally verify that the owner segment of `payload.dig('repository', 'full_name')` matches `repository_owner` (or reject payloads where they diverge) before dispatching to handlers. Alternatively, have `Handler#repository_name` receive the already-verified `repository_owner` value from the controller and refuse to resolve a `Repository` whose `owner` differs from it.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with distinct `webhook_secret`s (as supported by `Shipit.github(organization:)`).
2. As an administrator of `org-a` (who legitimately possesses `org-a`'s `webhook_secret`), craft a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
3. Sign the raw body with `org-a`'s `webhook_secret` per `Hook::DeliverySigner`/`GithubApp#verify_webhook_signature` scheme and send it as `X-Hub-Signature` to `POST /github/webhooks` with header `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` to `org-a`, fetches `org-a`'s app, and the signature validates successfully [5](#0-4) .
5. `PushHandler#process` (via `Handler#repository_name`) resolves the repository using `full_name` = `org-b/victim-repo`, not `org-a`, and triggers `sync_github` on `org-b`'s stacks [7](#0-6)  — a repository the attacker neither owns nor has the correct webhook secret for.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
