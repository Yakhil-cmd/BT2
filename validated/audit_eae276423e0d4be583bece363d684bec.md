### Title
Webhook signature verified against `repository.owner.login`'s org secret while handlers act on the independently-supplied `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/org's `webhook_secret` to validate the `X-Hub-Signature` against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (or falls back to `organization.login`) [1](#0-0) . Once verified, the raw payload is dispatched unchanged to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [2](#0-1) . However, the handlers that actually mutate state (`Repository`, `Stack`, review-stack provisioning, PR labels/close, etc.) locate the target repository via a *different* field of the same attacker-controlled payload: `payload.dig('repository', 'full_name')` [3](#0-2) , as seen concretely in `PullRequest::OpenedHandler#repository` [4](#0-3) . Nothing checks that `full_name`'s owner segment equals the `owner.login`/`organization.login` value that was used to select the verifying secret.

### Finding Description
The engine supports multi-organization configuration where each org has its own `webhook_secret` [5](#0-4) , exactly the scenario shown in `test/dummy/config/secrets_double_github_app.yml` with `OrgOne` and `OrgTwo` each having independent secrets.

The controller's authentication step is:
1. Determine `repository_owner` = `params.dig('repository','owner','login')` fallback `params.dig('organization','login')` [6](#0-5) .
2. Fetch `Shipit.github(organization: repository_owner)` and verify the HMAC signature against that org's `webhook_secret` [7](#0-6) .

Nothing ties this authenticated org identity to the repository record that will be looked up and written to downstream: `Handler#repository_name` reads `payload.dig('repository','full_name')` independently, and this is what feeds `Repository.from_github_repo_name(...)` used to select the `Stack`/`Repository` object that handlers act on (create teams/users, provision or close review stacks, add/remove labels, capture status, etc.) [8](#0-7) [9](#0-8) .

This breaks the intended binding:
`organization that authenticated the request == organization owning the repository that gets written`

Because `owner.login`/`organization.login` and `repository.full_name` are two independently-controlled JSON fields in the same unsigned-until-verified request body, and the HMAC only covers the raw body as a whole (so it can't selectively bind one field over another at the application logic level), an attacker who possesses (or can compute/obtain) a valid webhook secret for **any one** organization configured on the Shipit instance can:
- Set `repository.owner.login` (or `organization.login`) to that organization they control the secret for, so `verify_signature` succeeds.
- Set `repository.full_name` to `"other-org/other-repo"` — an entirely different, unrelated organization/repository also configured on the same Shipit instance.
- The signature check passes (it only validates against the org named in `owner.login`), and the handler then acts on the victim repository named in `full_name`.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" boundary explicitly called out in scope. Concretely reachable handlers that create/mutate cross-org state using only `full_name` include:
- `PullRequest::OpenedHandler`/`ReopenedHandler`, which provision review stacks (creating `Stack` records, potentially triggering deploy pipelines) for the targeted repository based solely on `full_name` [10](#0-9) .
- `PullRequest::ClosedHandler`, `Labeled`/`Unlabeled`/`LabelCapturing` handlers, which mutate review-stack lifecycle and labels for the resolved repository.
- `Repository.from_github_repo_name` resolution is entirely payload-driven, with no cross-check against the authenticating org.

This allows a party with legitimate webhook-secret knowledge for one configured org to forge writes (spurious deploy/rollback-adjacent review-stack creation/teardown, stack state changes) against a repository belonging to a different, unrelated org hosted on the same multi-tenant Shipit instance — an unauthorized cross-repository/cross-organization state change satisfying the "cross-repository writes" High/Critical impact criterion.

### Likelihood Explanation
Requires the Shipit instance to be configured for multiple GitHub organizations (`config/secrets*.yml` with per-org `webhook_secret` — supported and documented) and requires the attacker to know a valid webhook secret for at least one of the configured orgs (e.g. one they legitimately administer, or one with `webhook_secret` unset — since `verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank [11](#0-10) ). In a shared/multi-tenant Shipit deployment onboarding several orgs, at least one org without a configured secret, or one attacker-controlled org, is a realistic scenario, making this a plausible tenant-isolation break rather than a purely theoretical one.

### Recommendation
After the payload is parsed, verify that `params.dig('repository','owner','login')` (the value used to select the signature-verifying app) matches the owner segment of `params.dig('repository','full_name')` (and of `organization.login` when present) before dispatching to handlers, rejecting the request with `422` on mismatch. Alternatively, pass the authenticated `repository_owner` down into `Handler` and have `repository_name`/`from_github_repo_name` resolution refuse to resolve any repository whose owner does not equal the authenticated org.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` (attacker-controlled secret) and `orgB` (victim), per `test/dummy/config/secrets_double_github_app.yml` pattern.
2. Attacker crafts a `pull_request` "opened" webhook payload:
   ```json
   {
     "action": "opened",
     "number": 1,
     "repository": { "owner": {"login": "orgA"}, "full_name": "orgB/victim-repo" },
     "pull_request": { ... },
     "sender": {"login": "attacker"}
   }
   ```
3. Attacker signs the raw body with `orgA`'s `webhook_secret` and sets `X-Hub-Signature` accordingly.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgA")` and the signature validates successfully [7](#0-6) .
5. `PullRequest::OpenedHandler` resolves `repository` via `params.repository.full_name` = `"orgB/victim-repo"` [4](#0-3)  and provisions/mutates review-stack state for `orgB`'s repository, despite the request never having been authenticated by `orgB`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L8-54)
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

          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
