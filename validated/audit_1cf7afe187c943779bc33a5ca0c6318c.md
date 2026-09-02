This confirms the multi-org configuration model is deliberately supported by the engine, but the webhook verification and handler dispatch never re-check that the verified org matches the target repository's owner.

### Title
Cross-tenant webhook forgery in `EditedHandler#repository` due to missing organization/repository ownership binding - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` resolves the GitHub App/secret to use for HMAC verification solely from `params.dig('repository', 'owner', 'login')` (`repository_owner`), then dispatches the entire raw JSON body — including an attacker-controlled `repository.full_name` — to `EditedHandler.call(params)` without re-checking that the verified organization matches the repository the handler ultimately mutates. Because Shipit explicitly supports multiple independently configured GitHub orgs each with its own `webhook_secret`, an attacker who legitimately controls one small org's Shipit GitHub App can sign a payload with their own secret while setting `repository.full_name` to point at any other tracked repository, and `EditedHandler` will use that field to look up and mutate the victim's `PullRequest`.

### Finding Description
The broken binding, stated explicitly: the organization used to verify the HMAC, `repository_owner = params.dig('repository','owner','login')` used in `Shipit.github(organization: repository_owner)` [1](#0-0) , must equal the organization that owns the repository actually mutated by the handler, `Shipit::Repository.from_github_repo_name(params.repository.full_name).owner` [2](#0-1) . Nothing in the code enforces this equality.

Trace:
1. `verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`), calls `Shipit.github(organization: repository_owner)`, and checks `verify_webhook_signature` against that org's configured `webhook_secret` [3](#0-2) .
2. `Shipit.github` looks up per-organization config via `github_app_config(organization)` when multiple orgs are configured, each with an independent `webhook_secret` — this multi-tenant configuration is a first-class documented feature [4](#0-3) . Signature verification itself is `HMAC-sha1` over the raw body against that specific org's secret [5](#0-4) .
3. On success, `#create` parses the SAME raw body and dispatches it to every handler for the event, unconditionally: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [6](#0-5) .
4. `EditedHandler#repository` derives the target repository purely from `params.repository.full_name`, independent of `repository_owner` used in step 1: `Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new` [2](#0-1) .
5. `EditedHandler#process` then updates the matched `PullRequest`'s `github_pull_request` (title/state/etc.) from `params.pull_request`: `pull_request.update(github_pull_request: params.pull_request) if pull_request.present?` [7](#0-6) .

Root cause: `full_name` (used to select the target repository record) and `owner.login` (used to select the verifying secret) are two independent fields read from the same attacker-controlled JSON body, and no code anywhere compares them. An attacker who administers their own org (`attacker-org`) with a legitimately-configured `webhook_secret` can compute a correct signature over a body where `repository.owner.login = "attacker-org"` (satisfying `verify_signature`) but `repository.full_name = "victim-org/private-repo"` (consumed by `EditedHandler`). This passes all existing guards: `drop_unhandled_event` only checks the event type is registered [8](#0-7) ; `verify_signature` only checks the HMAC against the org resolved from `owner.login`, which succeeds because that IS the attacker's own real secret; `ExplicitParameters` schemas in the handler only validate types/presence of fields like `repository.full_name` being a String, not cross-field consistency with the org that authenticated the request [9](#0-8) .

This same pattern (repository resolved solely by `params.repository.full_name`, decoupled from the verifying org) is repeated across other `PullRequest` handlers — `OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `AssignedHandler`, `LabeledHandler`, `LabelCapturingHandler` — all sharing the identical `repository` method pattern [10](#0-9) [11](#0-10) , so the impact is not limited to `EditedHandler` alone, though the question scopes to it specifically.

### Impact Explanation
An attacker who legitimately controls a single small org's Shipit GitHub App installation (and thus its own real `webhook_secret`) can forge webhook bodies that mutate `Shipit::PullRequest` records belonging to ANY other tracked repository across ANY other tenant org configured in the same Shipit instance, since `EditedHandler` never checks `repository.owner.login == repository_owner` (the org that verified the signature). Per request, the attacker can overwrite title/state/labels/etc. of an arbitrary victim `PullRequest` by matching `params.number` to an existing PR number in `victim-org/private-repo`. This is repeatable arbitrarily and generalizes across every repository/stack tracked by the instance — a cross-tenant record-mutation vulnerability matching the "payload for one repository mutating another's stack" Critical category.

### Likelihood Explanation
Preconditions: the Shipit instance must be configured with the multi-org `github:` secrets schema (explicitly documented and supported) so that the attacker's own org has a distinct, attacker-known `webhook_secret` [12](#0-11) ; the victim repository must be tracked by the same Shipit instance. Attacker cost is minimal: no privileged Shipit role, session, or victim secret is required — only the attacker's own legitimately-issued webhook secret for their own org, which they hold by design. The attack is a single unauthenticated (from Shipit's perspective, "authenticated" only insofar as HMAC over attacker's own secret) HTTP POST to `/webhooks`, fully repeatable.

### Recommendation
In `verify_signature` (or in each handler's `repository` resolution), enforce that the organization used to compute/verify the HMAC equals the owner of the repository named in the payload, e.g. compare `repository_owner` (or the resolved `Repository#owner`) against `params.dig('repository','owner','login')`/`full_name.split('/').first` and reject (422) on mismatch before dispatching to handlers. Alternatively, centralize this check in `WebhooksController#create` by re-deriving `repository_owner` from `full_name` and asserting equality with the value used in `verify_signature`, so no handler can be reached with a body whose resolved repository belongs to an organization other than the one that authenticated the delivery.

### Proof of Concept
minitest plan under `test/controllers/webhooks_controller_test.rb` style (no live GitHub):
1. Configure two orgs in test secrets, `attacker-org` with `webhook_secret: "attacker-secret"` and `victim-org` (owning tracked repository/stack/pull_request fixtures) with its own distinct secret.
2. Build `payload = { action: 'edited', number: <victim_pr.number>, pull_request: { ..., title: 'PWNED' }, repository: { full_name: 'victim-org/private-repo', owner: { login: 'attacker-org' } }, sender: { login: 'attacker' } }.to_json`.
3. Compute `signature = "sha1=" + OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', payload)`.
4. `request.headers['X-Github-Event'] = 'pull_request'; request.headers['X-Hub-Signature'] = signature`.
5. `post :create, body: payload, as: :json` — assert `response.status == 200` (verify_signature resolves `Shipit.github(organization: 'attacker-org')` and succeeds using the attacker's own real secret).
6. Assert both sides of the binding: `repository_owner_used_for_verification = 'attacker-org'` vs `Shipit::PullRequest#reload.stack.repository.owner == 'victim-org'` — assert these differ, and assert `victim_pr.reload.title == 'PWNED'`, proving the victim record was mutated by a signature that verified against a different org's secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L63-65)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
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
