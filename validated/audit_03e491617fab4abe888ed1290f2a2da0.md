### Title
Webhook signature verification binds to `repository.owner.login`, but event processing trusts the unrelated `repository.full_name` field, allowing cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/secret used to authenticate an inbound webhook by reading `repository.owner.login` (or `organization.login`) out of the **unauthenticated** JSON body, then checks the HMAC signature against that org's `webhook_secret`. [1](#0-0)  Once verification passes, every event handler (`Shipit::Webhooks::Handlers::Handler`) resolves the target `Repository`/`Stack` using a **different** field of the same payload, `repository.full_name`, with no cross-check against the field used for signature-org selection. [2](#0-1) 

### Finding Description
The binding the engine relies on is: *"the organization whose secret authenticated the request" == "the repository the request is allowed to act on."* The verification path establishes only the first half:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

`Shipit.github(organization:)` looks up per-organization config (secret, app id, etc.) when the deployment uses the multi-organization `github:` config format documented in `docs/setup.md`. [4](#0-3)  This means each onboarded GitHub organization has its own independently known `webhook_secret` — an organization admin legitimately creating their own GitHub App knows their own secret. [5](#0-4) 

After `verify_signature` passes, the handler that actually processes the event never re-derives or re-checks `repository_owner`. Instead it independently reads:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`repository.owner.login` and `repository.full_name` are two independent JSON fields inside the same request body. A org admin who has legitimately been onboarded (organization `A`, with a real, self-known `webhook_secret_A`) can craft an arbitrary raw JSON payload where `repository.owner.login = "A"` (so `verify_signature` selects and validates against `webhook_secret_A`, which they know and can self-sign) while setting `repository.full_name = "victim-org/victim-repo"` — a completely different repository/stack already configured in the same Shipit instance. The signature check only validates that *some bytes were HMAC'd with org A's secret*; it never asserts that the `full_name` inside those bytes actually belongs to org A.

Concretely this breaks the equality:
`organization-that-authenticated (repository.owner.login) == repository-that-is-written (repository.full_name)`

which the rules identify as an in-scope, unprivileged-attacker-exploitable binding.

### Impact Explanation
Once the forged payload is accepted, any handler can be driven against the victim repository's stacks:
- `PushHandler` enqueues `GithubSyncJob` for any not-archived stack on a forged branch/`after` SHA, causing Shipit to sync/deploy state for a repository the attacker does not control. [6](#0-5) 
- `StatusHandler` creates a fake CI status (`create_status_from_github!`) for any commit SHA that matches, which can flip a victim stack's commits to "success," bypassing real CI gating for deploys. [7](#0-6) 
- `CheckSuiteHandler` schedules check-run refreshes on the victim's commits for the forged head SHA/branch. [8](#0-7) 

Forging passing CI status via `StatusHandler` for a victim repository's commit can enable an unauthorized/automatic deploy of that commit if the victim stack has continuous deployment enabled, satisfying the "unauthorized deploy" Critical-impact bar defined in the rules.

### Likelihood Explanation
Exploitation requires only that the attacker control (or be able to legitimately create) one GitHub organization/App already onboarded into the same multi-org Shipit deployment — a scenario explicitly supported and documented by this engine (`docs/setup.md`'s "Using Multiple Github Applications" section). [4](#0-3)  No GitHub write access to the victim repository, no Shipit session, and no knowledge of the victim's or Shipit's secrets is needed — only the attacker's own legitimately-issued webhook secret for their own onboarded org, which they control by design. This is a realistic multi-tenant configuration, not a hypothetical misuse of the engine.

### Recommendation
After signature verification, re-validate that `repository.full_name` (and `repository.owner.login`) is actually owned by / consistent with the organization whose secret verified the signature (`repository_owner`) before dispatching to handlers — e.g., reject the webhook if `payload.dig('repository','full_name')&.split('/')&.first != repository_owner`. Alternatively, have handlers derive the target repository/organization strictly from the same field used for signature-org selection, rather than trusting a second, unrelated payload field.

### Proof of Concept
1. Deploy Shipit configured with multiple organizations, e.g. `orgA` (attacker-controlled, `webhook_secret_A` known to the attacker because they created that GitHub App) and `orgV` (victim, has a `Repository`/`Stack` configured in this Shipit instance). [4](#0-3) 
2. Attacker builds a JSON body for a `status` event:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgV/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_A, raw_body)>` themselves, since they legitimately possess `webhook_secret_A`.
4. POST to `/webhooks` with header `X-Github-Event: status`.
5. `WebhooksController#verify_signature` computes `repository_owner = "orgA"`, fetches `Shipit.github(organization: "orgA")`, and the HMAC check succeeds because the attacker signed with the correct secret for `orgA`. [9](#0-8) 
6. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which looks up `Commit.where(sha: params.sha)` — matching the victim's commit under `orgV` — and calls `create_status_from_github!`, injecting a forged CI status onto a repository the attacker never authenticated against. [7](#0-6)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
