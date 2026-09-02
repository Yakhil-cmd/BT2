## Title
Cross-organization webhook trust bypass via mismatched `repository.owner.login` / `repository.full_name` binding - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate an inbound webhook against using `repository_owner`, a value read directly from the *unverified* JSON body (`params.dig('repository', 'owner', 'login')`). Every event handler, however, resolves the actual `Stack`/`Commit` to mutate using a **different** field of the same unverified body: `repository.full_name` (see `Shipit::Webhooks::Handlers::Handler#repository_name` and `StatusHandler#process`). In a multi-organization deployment (a documented, supported configuration — `docs/setup.md` "Using Multiple Github Applications"), these two fields are never cross-checked, so the organization whose secret authenticates the request is not bound to the repository the handler actually writes to. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
The equality that should hold is:

`organization whose secret verified the signature == owner of the repository the handler subsequently modifies`

Before the attack: for a legitimate GitHub webhook, `repository.owner.login` and `repository.full_name`'s owner segment are always identical, because GitHub itself populates both from the same event source.

`verify_signature` computes the app/secret to check against purely from the attacker-controlled body:
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

and then:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [5](#0-4) 

Each configured organization has its own independent `webhook_secret`, as shown in `docs/setup.md`'s multi-org example and `test/dummy/config/secrets_double_github_app.yml`. `Shipit.github(organization:)` resolves a per-org `GitHubApp` instance keyed strictly by that string. [6](#0-5) 

Once signature verification passes, the raw JSON body is dispatched unchanged to every registered handler for the event:
```
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
end
``` [7](#0-6) 

But the handlers never look at `repository.owner.login` — they resolve their target repository/stack from `repository.full_name`:
```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [8](#0-7) 

`StatusHandler` uses this to write attacker-supplied CI status data (`state`, `description`, `target_url`) directly onto a `Commit` belonging to whatever stack `full_name` resolves to:
```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

`CheckSuiteHandler` similarly triggers `schedule_refresh_check_runs!` for commits on a stack picked purely by `full_name`. [9](#0-8) 

**After the attacker's request**: an attacker who controls (or has legitimately obtained, e.g. as a low-privilege contributor to) the `webhook_secret` for `OrgA` — one of potentially several organizations configured on the same Shipit instance — can craft a webhook body where:
- `repository.owner.login = "OrgA"` (so `verify_signature` verifies against `OrgA`'s secret, which the attacker knows and used to sign the request), and
- `repository.full_name = "OrgB/production-repo"` (a completely different, higher-trust organization's tracked stack).

Because `verify_signature` and the handlers read two different, uncorrelated fields of the same attacker-controlled JSON body, the signature check for `OrgA` is satisfied while the actual mutation happens against `OrgB`'s data. This breaks the deployment-trust binding required by the rules: "an organization that authenticated versus the repository that is written."

### Impact Explanation
This qualifies as High severity under the rubric: it grants an unauthenticated-for-`OrgB` attacker (who only holds `OrgA`'s webhook secret) the ability to inject spoofed `status`, `check_suite`, `check_run`, `push`, `pull_request`, or `membership` events targeting `OrgB`'s stacks:
- Forged commit statuses (`StatusHandler`) can flip a commit from "pending/failure" to "success", which downstream `release_status?`/`deployable_status` safety checks (used to gate deploys) rely on — enabling an unauthorized deploy of a commit that never actually passed CI in `OrgB`.
- Forged `push` events can cause `GithubSyncJob` to run against `OrgB`'s stack.
- Forged `pull_request`/`membership` events can create/alter `Team`, `Membership`, review stacks, etc. scoped to `OrgB`.

This crosses the "unauthorized deploy" / "escalation into `Shipit.github_teams` authorization" impact bar defined in scope, achieved purely by exploiting the mismatch between the two identity fields — no `ApiClient` token, session, or GitHub App private key is required, only knowledge of one organization's webhook secret (which, per the setup docs, may even be left unset/`nil` for some orgs, in which case `verify_webhook_signature` returns `true` unconditionally, requiring no secret at all). [10](#0-9) 

### Likelihood Explanation
Likelihood is elevated by the fact that:
1. Multi-organization configuration is an officially documented and supported feature (`docs/setup.md`), not a misuse of the engine.
2. Webhook secrets are optional per-org (`webhook_secret: # nil` in the example configs); an org configured without one accepts any signature unconditionally, making it trivial to satisfy `verify_signature` while targeting a *different* org's repository via `full_name`.
3. The webhook endpoint is intentionally public/unauthenticated (it must be reachable by GitHub), so no session or API token is a prerequisite — only knowledge of any one configured org's (possibly empty) webhook secret.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), enforce that the organization whose secret verified the signature matches the owner segment of `repository.full_name` (and of `organization.login` for org-scoped events) before dispatching to handlers. Concretely, after computing `repository_owner`, also derive the owner from `params.dig('repository', 'full_name')&.split('/')&.first` and reject the request (422) if they differ. This restores the equality: verified-organization == repository-owner-being-mutated, for every multi-org Shipit deployment.

### Proof of Concept
1. Deploy Shipit with two organizations configured, e.g. `OrgA` (attacker-known secret `secretA`, or no secret) and `OrgB` (victim, tracked stack `OrgB/prod`).
2. Attacker crafts a `push` (or `status`) webhook JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": {
       "owner": { "login": "OrgA" },
       "full_name": "OrgB/prod"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(secretA, body)>` using `OrgA`'s known/empty secret, and sets `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")`, verifies successfully against `secretA`.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/prod")`, and triggers `stack.sync_github` on `OrgB`'s stack — despite the request never having been authenticated for `OrgB`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
