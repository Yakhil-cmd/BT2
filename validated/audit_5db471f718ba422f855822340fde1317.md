### Title
Webhook HMAC signature is bound to `repository.owner.login`/`organization.login`, but the event is applied to whichever `repository.full_name` the payload claims — allowing a valid signer for one GitHub organization to forge events against another organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to validate an inbound webhook using the organization derived from `repository.owner.login` (falling back to `organization.login`), while every default event handler resolves the actual `Repository`/`Stack` to act on using the independent `repository.full_name` field of the same JSON body. Because these two fields are never cross-validated, a party who legitimately controls one organization's webhook secret (a normal Shipit-integrated GitHub organization, not a privileged Shipit account) can submit a payload whose `owner.login`/`organization.login` matches their own org (so it authenticates) but whose `repository.full_name` names a stack belonging to a completely different organization. This lets an unprivileged-relative-to-Shipit organization forge `push`, `status`, `check_suite`, `pull_request` and `membership` events against another tenant's repositories.

### Finding Description
`verify_signature` computes the signing organization from the payload itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up a per-organization `GitHubApp` config (each with its own `webhook_secret`), and raises `Shipit::GithubOrganizationUnknown` for unrecognized organizations — confirming the engine is designed to host multiple, mutually untrusted GitHub organizations side by side, each authenticated with its own secret: [3](#0-2) 

Once the HMAC check passes, the raw JSON is dispatched unchanged to every registered handler for the event: [4](#0-3) 

Every default handler, however, determines *which* repository/stack to mutate using a different field — `repository.full_name` — with no comparison back to the field that was actually verified (`repository.owner.login`): [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

**The binding that should hold but doesn't:** `organization authenticated by the HMAC (repository.owner.login / organization.login)` == `repository/organization whose Stack is written (repository.full_name)`. Nothing in `WebhooksController` or `Handler` enforces this equality — the two lookups are performed on independent JSON paths of the same attacker-controlled body, and only the raw bytes (not their semantic consistency) are covered by the signature.

### Impact Explanation
An organization that is a legitimate Shipit tenant (knows only its own `webhook_secret`, has no Shipit account privileges and no write access to any other tenant's GitHub repository) can sign an arbitrary payload with its own secret and set `repository.full_name` to another tenant's `owner/repo`:
- `status` event → `StatusHandler` creates a fabricated commit `Status` (e.g., CI "success") on another organization's tracked commit, which can satisfy required/blocking statuses and enable an **unauthorized deploy** of that victim stack.
- `push` event → `PushHandler` triggers `GithubSyncJob` for the victim's stacks with an attacker-chosen `expected_head_sha`.
- `pull_request` event → creates/manipulates review stacks belonging to the victim repository.
- `membership` event → is scoped to `organization.login` used for signing, so less directly exploitable, but confirms the multi-tenant secret model.

This is a cross-repository/cross-organization write achieved purely by exploiting a payload-field vs. signed-field mismatch, matching the "organization authenticated vs. repository written" binding break called out as in-scope. The most severe outcome (forged CI status enabling an unauthorized deploy) is Critical.

### Likelihood Explanation
Any organization onboarded to a multi-tenant Shipit deployment already possesses a valid `webhook_secret` for its own GitHub App/organization — this is not a privileged Shipit credential, an `ApiClient` token, or `api_clients_secret`; it is the ordinary secret every integrated GitHub org is issued so its own webhooks can be verified. Crafting the forged payload requires no GitHub or Shipit privilege beyond that, only knowledge of another tenant's `owner/repo` name (public information). No TLS interception, social engineering, or host misconfiguration is required.

### Recommendation
In `WebhooksController#verify_signature` (or immediately after in `#create`), assert that the organization used to select/verify the signature is the same organization implied by `repository.full_name` (and `organization.login` for org-scoped events) before dispatching to any handler — i.e., reject the request if `repository.full_name.split('/').first` does not case-insensitively equal `repository_owner`. Equivalently, have handlers resolve stacks by the *verified* organization only, never trusting `repository.full_name` alone to select the target tenant.

### Proof of Concept
```
# Org "attacker-org" has a legitimate Shipit GitHub App with webhook_secret = S_attacker
# Victim stack tracks "victim-org/victim-repo"

body = {
  "sha" => "<victim commit sha>",
  "state" => "success",
  "context" => "ci/required-check",
  "repository" => {
    "owner" => { "login" => "attacker-org" },   # used by verify_signature -> resolves S_attacker
    "full_name" => "victim-org/victim-repo"     # used by StatusHandler -> resolves victim's Stack
  }
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest('sha1', S_attacker, body)

POST /webhooks
X-Github-Event: status
X-Hub-Signature: <signature>
body: <body>

# verify_signature succeeds (secret matches attacker-org's own app)
# StatusHandler#process creates a fabricated "success" Status on victim-org/victim-repo's commit,
# potentially satisfying required/blocking statuses and permitting an unauthorized deploy.
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit.rb (L62-63)
```ruby
  GithubOrganizationUnknown = Class.new(StandardError)
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
