### Title
Cross-organization webhook forgery: signature verified against `repository.owner.login`'s secret while handlers act on `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit` supports a multi-organization GitHub App configuration where each organization has its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` selects which organization's `GitHubApp` (and therefore which `webhook_secret`) to verify the HMAC signature against using `repository_owner`, a value read directly from the untrusted JSON payload (`repository.owner.login` or `organization.login`) [2](#0-1) . Once the signature is accepted, the actual event handlers resolve the target `Repository`/`Stack` using a *different* field from the same payload, `repository.full_name` [3](#0-2) [4](#0-3) . Nothing enforces that `repository.owner.login` (the field used to pick the verifying secret) matches the owner encoded in `repository.full_name` (the field used to pick the acted-upon repository).

### Finding Description
The binding that should hold is: **the organization whose secret authenticated the webhook == the organization owning the repository the handler mutates**. In practice:

- `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, and verifies the HMAC over the *entire* raw body against that organization's configured `webhook_secret` [5](#0-4) .
- After the signature check passes, `WebhooksController#create` dispatches the same JSON payload to handlers, e.g. `PushHandler`, `OpenedHandler` (pull_request), etc. [6](#0-5) .
- These handlers resolve the `Repository`/`Stack` to act on purely from `payload.dig('repository', 'full_name')` [3](#0-2) , or `params.repository.full_name` in the pull-request handlers [7](#0-6) .

Because `repository.owner.login` and `repository.full_name` are independent, attacker-controlled JSON strings within the same signed body, an attacker who legitimately controls (or knows the `webhook_secret` for) **one** configured organization in a multi-tenant Shipit deployment can craft and correctly HMAC-sign a payload where:
- `repository.owner.login` = the attacker's own organization (so `Shipit.github(organization: ...)` resolves to a `GitHubApp` whose secret the attacker knows, and the signature check passes), while
- `repository.full_name` = `"<victim-org>/<victim-repo>"`, an entirely different organization's repository also configured in the same Shipit instance.

The signature check validates only "this body was signed with organization A's secret" — it never validates "and organization A is authorized to act on the repository referenced inside this body." The handler layer trusts `repository.full_name` unconditionally to locate the `Stack`/`Repository` to mutate.

### Impact Explanation
This breaks the deployment-trust binding "an organization that authenticated versus the repository that is written," which the assignment explicitly calls out as in-scope. Depending on the event type dispatched, this allows an attacker who controls one tenant/org's webhook secret to trigger, against a victim organization's repository, actions such as `GithubSyncJob` (push events) [8](#0-7) , review-stack provisioning/merges via `ReviewStackAdapter` (pull_request events) [9](#0-8) , commit-status writes, or membership/team mutations — i.e., cross-repository writes and unauthorized triggering of deploy-adjacent workflows for a repository the attacker does not own.

### Likelihood Explanation
Requires the attacker to already be a legitimate/authenticated organization tenant in a multi-org Shipit deployment (knows their own `webhook_secret`), then simply crafts a JSON body with mismatched `repository.owner.login` vs `repository.full_name` fields and signs it themselves. No GitHub-side control over the victim org or repository is needed. Likelihood is moderate-to-high in any deployment using the multi-organization `github` config, and only applicable to that configuration mode (single-org configs collapse `repository_owner` resolution to a fixed config, per `github_default_organization`) [10](#0-9) .

### Recommendation
In `WebhooksController#verify_signature`, after resolving the signing organization, cross-check that the resolved organization matches the owner segment of `payload.dig('repository', 'full_name')` (and `organization.login` when present) before dispatching to handlers; reject with `422` on mismatch.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (multi-org `secrets.github` schema).
2. Attacker (knowing `attacker-org`'s `webhook_secret`) crafts a `pull_request` webhook JSON body:
   ```json
   {
     "action": "opened",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
     "pull_request": { ... },
     "sender": { "login": "attacker" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, raw_body)` and POSTs to `/github/webhooks`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `GitHubApp`, verifies the signature successfully [11](#0-10) .
5. `OpenedHandler` resolves `repository` via `Shipit::Repository.from_github_repo_name("victim-org/victim-repo")` [4](#0-3)  and provisions/mutates a review stack belonging to `victim-org`, despite the request never being signed by `victim-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
