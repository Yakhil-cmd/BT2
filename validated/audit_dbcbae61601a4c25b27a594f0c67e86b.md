### Title
Webhook signature is verified against the org derived from `repository.owner.login`/`organization.login`, but handlers act on the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Staker::setRewardsFeeBps` illustrates a class of bug where a value used to authorize/compute a later action is taken from a different source than the value that was actually validated. In `Shipit::WebhooksController`, the field used to select which organization's webhook secret verifies the HMAC signature (`repository.owner.login`, falling back to `organization.login`) is not required to be the same field the event handlers use to select which `Stack`/`Repository` the webhook acts on (`repository.full_name`). In a multi-organization Shipit deployment (`Shipit.github(organization: ...)` supports one `GitHubApp`/secret per org), this breaks the binding "organization authenticated == repository written."

### Finding Description
`verify_signature` picks the `GitHubApp` (and therefore the HMAC secret) to check using the request body itself, before that body has been proven authentic: [1](#0-0) [2](#0-1) [3](#0-2) 

`repository_owner` is derived from `params.dig('repository', 'owner', 'login')`, falling back to `params.dig('organization', 'login')`. `Shipit.github(organization: repository_owner)` resolves to a distinct `GitHubApp`/`webhook_secret` per organization in a multi-tenant config: [4](#0-3) 

Once the signature check passes (using the secret belonging to whatever org `repository_owner` names), the *entire* raw JSON body — including an attacker-controlled `repository.full_name` — is handed unchanged to every registered handler: [5](#0-4) 

Handlers never re-derive the target `Stack`/`Repository` from the organization that was authenticated; they instead trust `repository.full_name` (or `repository.owner.login`+`name`) taken straight from the same payload to look up any repository/stack in the whole install: [6](#0-5) [7](#0-6) 

This means the field that determines *whose secret signs the request* (`repository.owner.login` / `organization.login`) is never required to equal the field that determines *which repository/stack is mutated* (`repository.full_name`). An attacker who legitimately controls one onboarded GitHub organization (and therefore knows/owns that org's `webhook_secret`) can craft a payload where `repository.owner.login` (or `organization.login`) is their own org — so `verify_signature` selects and validates against their own secret — while `repository.full_name` names a completely different, victim organization's repository. Because the signature only proves the payload was signed with *some* configured secret, not that the secret's owning org matches the repository the payload claims to act on, this forges valid-looking webhook events for arbitrary repositories/stacks belonging to other tenants of the same Shipit instance.

Concretely exploitable handlers include:
- `PushHandler`, which triggers `GithubSyncJob` (resyncs commits) for any stack matched via `Repository.from_github_repo_name(repository.full_name)`: [8](#0-7) 
- The `pull_request` handlers (`OpenedHandler`, `ClosedHandler`, etc.), which create/archive review stacks for any `Repository.from_github_repo_name(params.repository.full_name)`: [9](#0-8) 

### Impact Explanation
This crosses a genuine tenant/repository boundary in a multi-org Shipit deployment: possession of one organization's webhook secret is sufficient to forge webhook state changes (commit sync triggers, review-stack provisioning/archival) against any other organization's repositories configured on the same instance, i.e. **cross-repository writes** performed with the app's own GitHub credentials for the victim's repos (`stack.github_api`/`Shipit.github(organization: owner)` in `GithubSyncJob`/`Repository#github_app`). This matches the "cross-repository writes" Critical-tier impact category.

### Likelihood Explanation
Likelihood is Medium: it requires the attacker to be an authenticated tenant of the Shipit instance (i.e., to control the webhook secret for at least one organization already configured in `Shipit.github`), which is a real but non-trivial precondition — it is not exploitable by a fully unauthenticated internet attacker against a single-organization deployment (the common case), but is directly exploitable in any multi-org configuration, which the codebase explicitly supports (`github_app_config`, `github_organizations`).

### Recommendation
After `verify_signature` succeeds, re-derive/validate that the organization whose secret matched the signature (`repository_owner`) is the same organization named in `repository.full_name` (or reject/ignore the event otherwise) before dispatching to handlers. Alternatively, have handlers resolve the target `Repository`/`Stack` using the authenticated `repository_owner` rather than trusting `repository.full_name` verbatim, and assert equality between the two before acting.

### Proof of Concept
1. Attacker controls organization `attacker-org`, onboarded on the shared Shipit instance with its own `webhook_secret` (`attacker-org` app config in `secrets.github`).
2. Attacker crafts a `push` webhook payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker signs the raw body with `attacker-org`'s known `webhook_secret` and sets `X-Hub-Signature` accordingly, `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates the HMAC — it passes, because the attacker knows that secret.
5. `PushHandler#process` runs `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues a `GithubSyncJob` for the victim's stack, causing the app to fetch/act on the victim repository using the app's own GitHub credentials — despite the attacker never having proven any relationship to `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
