### Title
Webhook organization used for signature verification is never bound to the repository the payload actually writes to - cross-organization sync/deploy trigger - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit.github(organization:)` selects a distinct `GitHubApp` (and its own `webhook_secret`) per GitHub organization when Shipit is configured with the multi-org schema [1](#0-0) . The webhook controller picks which organization's secret to verify the signature against directly from the untrusted JSON payload, and never re-checks that the field used for verification matches the field the downstream handler actually acts on.

### Finding Description
`WebhooksController#verify_signature` extracts `repository_owner` from the parsed request body (`params.dig('repository', 'owner', 'login')` or the `organization.login` fallback) and uses it purely to pick which `GitHubApp`/`webhook_secret` to verify the HMAC signature against: [2](#0-1) .

Once the signature check passes, `create` hands the entire parsed body to the registered handler for the event, e.g. `PushHandler`: [3](#0-2) .

`Handler#stacks`/`#repository_name`, used by every handler (push, pull_request, etc.), derives the target `Repository` from a *different* payload field: `repository.full_name`, not `repository.owner.login`: [4](#0-3) . `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack matching that repository/branch: [5](#0-4) .

Nothing in the controller or in `Handler` enforces that `repository.owner.login` (the field used to select the signing secret) equals the owner segment of `repository.full_name` (the field used to select the `Repository`/`Stack` that gets synced). In the multi-org configuration (`secrets.github` keyed by organization, resolved via `github_app_config`) each organization has its own `webhook_secret`: [6](#0-5) , [7](#0-6) , [8](#0-7) . An operator running Shipit for several organizations owns/knows each organization's own webhook secret (it's a value they configured on their own GitHub App).

Binding broken as an equality: **organization that authenticated == repository that is written** is assumed but never enforced.
- Before: `repository.owner.login` (used to pick the verifying secret) and `repository.full_name`'s owner (used to pick the `Stack` acted upon) are implicitly assumed identical.
- After the attacker's request: an attacker who legitimately controls (and knows the webhook secret for) OrgA can send a POST to `/webhooks` with `X-Github-Event: push`, `repository.owner.login = "OrgA"` (so `verify_signature` resolves and validates against OrgA's own `webhook_secret`, which the attacker knows and can sign with), while setting `repository.full_name = "OrgB/victim-repo"` inside the same signed body. The signature check succeeds (it is validated against OrgA's secret over the full raw body, which the attacker fully controls and signs correctly), yet `PushHandler` resolves the target `Repository`/`Stack` from `OrgB/victim-repo` and calls `stack.sync_github(expected_head_sha: ...)`.

### Impact Explanation
This lets an attacker who only controls an unrelated, less-trusted GitHub organization onboarded to the same Shipit instance trigger `GithubSyncJob`/`sync_github` (and, depending on handler, other stack-mutating actions such as archiving/unarchiving review stacks or capturing labels) on stacks belonging to a completely different, victim organization/repository, without ever having any credential, membership, or webhook secret for that victim org. Forcing an out-of-band sync with an attacker-chosen `expected_head_sha` can influence what Shipit believes is the deployable head, which can cascade into unauthorized deploy behavior for stacks configured to auto-deploy on sync. This crosses the "cross-repository writes / unauthorized deploy" impact bar defined in scope.

### Likelihood Explanation
Requires Shipit configured with the multi-organization GitHub app schema (`secrets.github` keyed by org) — a supported and documented configuration [9](#0-8)  — and requires that the attacker control at least one onboarded organization (i.e., they know that org's own `webhook_secret`, which they legitimately set on their own GitHub App). No repository push access, no Shipit session, and no victim-org credentials are required, which fits the "unprivileged attacker breaking a deployment-trust binding" pattern the scan targets.

### Recommendation
After signature verification succeeds, verify that `repository.owner.login` (or `organization.login`) used to select the signing organization matches the owner segment of every repository referenced by the payload (`repository.full_name`) before dispatching to handlers, and reject the webhook (422) on mismatch. Alternatively, resolve the target `Repository` first and require its configured owning organization to equal the organization whose secret validated the signature.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `secrets.github.orga.webhook_secret` / `secrets.github.orgb.webhook_secret`).
2. As the operator of `OrgA` (attacker), craft a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Sign the raw JSON body with `OrgA`'s known `webhook_secret` using the same HMAC-SHA1 scheme Shipit expects: `algorithm=sha1; signature=HMAC-SHA1(webhook_secret, body)` (mirrors `GitHubApp#verify_webhook_signature`, [8](#0-7) ).
4. `POST /webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `OrgA`'s `GitHubApp`, and validates successfully because the attacker signed with `OrgA`'s real secret [10](#0-9) .
6. `PushHandler` resolves stacks via `repository.full_name = "OrgB/victim-repo"` [11](#0-10)  and calls `stack.sync_github(expected_head_sha: "deadbeef")` on every matching `OrgB` stack on branch `master` [5](#0-4) , despite the attacker having no relationship to `OrgB`.

### Citations

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
