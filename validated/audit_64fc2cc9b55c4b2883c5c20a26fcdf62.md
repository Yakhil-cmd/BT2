### Title
Webhook signature is scoped to the payload's `repository.owner.login` while every event handler acts on `repository.full_name` (or acts with no repository scope at all) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`), then hands the fully-parsed JSON body to handlers that resolve the target `Repository`/`Stack`/`Commit` using a *different* field of the same payload (`repository.full_name`), or, in the case of `StatusHandler`, using no repository scoping at all. The equality the engine implicitly assumes but never enforces is: `verified_owner(repository.owner.login) == acted_upon_repository(repository.full_name)`. In a multi-organization Shipit deployment (explicitly documented in `docs/setup.md` under "Using Multiple Github Applications"), each organization is provisioned its own, isolated `webhook_secret`. Nothing ties the `owner.login` field that selects the verifying secret to the `full_name` field that selects which tenant's data gets mutated.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` looks up a per-organization config (`app_id`, `installation_id`, `webhook_secret`) from `secrets.github` when multiple GitHub Apps are configured:
```ruby
def github(organization: github_default_organization)
  if github_default_organization.nil?
    config = secrets.github
  else
    config = github_app_config(organization)
    raise GithubOrganizationUnknown, organization if config.nil?
  end
  @github ||= {}
  @github[organization] ||= GitHubApp.new(organization, config)
end
``` [2](#0-1) 

So the *only* field of the payload used to pick which secret validates the HMAC is `repository.owner.login`. Once verification passes, the raw body is JSON-parsed and dispatched to handlers by event type only - `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` - with no re-validation that `repository.owner.login` matches anything the handler subsequently trusts.

`Shipit::Webhooks::Handlers::Handler` (the base class used by `push`, `check_suite`, and other repo-scoped handlers) resolves the target `Repository`/`Stack` from a *different* field:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`StatusHandler` goes further and does not scope by repository at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

This is structurally the same class of bug as the `RocketJoeStaking.lastRewardTimestamp` finding: a value the contract/engine trusts for one purpose (`joeSupply`/`repository.owner.login`) is not the same value, nor cross-checked against, the value actually used to compute state changes (`lastRewardTimestamp` initialization/`repository.full_name`, or in `StatusHandler`'s case, no scoping value at all). The verified field and the acted-upon field are decoupled.

### Impact Explanation
In the documented multi-organization configuration, each org's `webhook_secret` is meant to be an isolation boundary — an app installed for Org A should only be able to write Org A's data. Because the webhook signature is validated against `repository.owner.login` but the mutation target is selected by `repository.full_name` (or, for `status` events, not scoped at all), a payload correctly signed with Org A's `webhook_secret` but carrying `repository.full_name` pointing at Org B's tracked repository will pass verification and be processed against Org B's `Stack`/`Repository`/`Commit` records. For `status` events specifically, `Commit.where(sha:)` has zero repository scoping, so a validly-signed event from any configured organization can write a commit status onto any commit row in the entire installation whose SHA happens to match, regardless of which repository/organization it belongs to. Since Shipit gates deploys/CI checks on commit status, this enables cross-repository/cross-tenant writes and potentially an unauthorized deploy path if a commit's spoofed "success" status satisfies deploy CI gating (`ignore_ci`, deployable status checks) for a different tenant's stack — an impact matching "cross-repository writes / an unauthorized deploy."

### Likelihood Explanation
This requires possessing a legitimately-provisioned `webhook_secret` for *some* organization configured in the same multi-tenant Shipit instance (your own org's App secret), not the victim organization's secret and not any Shipit session/API token/private key. In the documented multi-org topology (`docs/setup.md`), that secret is handed out per-organization to that organization's own GitHub App owner, who is otherwise an "unprivileged" party with respect to every *other* organization hosted on the same Shipit instance. The engine's own code never enforces that the field used to select the verifying key and the field used to select the mutated record agree, so likelihood is driven entirely by whether the deployment hosts more than one organization behind the same instance — a supported, documented configuration, not a misconfiguration.

### Recommendation
After HMAC verification succeeds for `repository_owner`, re-derive the target repository from the same trusted field (`repository.owner.login`) rather than trusting `repository.full_name` independently, or explicitly assert `repository.full_name.downcase.start_with?("#{repository_owner.downcase}/")` before dispatching to handlers. For `StatusHandler`, scope `Commit.where(sha:)` by the verified repository/stack (e.g., join through `Stack -> Repository` matching the verified owner) instead of matching bare SHA across the entire installation.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own GitHub App and `webhook_secret` per `docs/setup.md`'s multi-app instructions.
2. As the legitimate owner of `org-a`'s GitHub App (holder of `org-a`'s `webhook_secret`, but with no access to `org-b`), craft a `status` event JSON body:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" },
  "sha": "<sha of a commit tracked in org-b's stack>",
  "state": "success"
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(org-a's webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"org-a"`, fetches `org-a`'s `GitHubApp`, and the signature validates successfully (it was computed correctly against `org-a`'s secret). [5](#0-4) 
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which runs `Commit.where(sha: params.sha)` with no repository filter and creates a commit status on `org-b`'s commit despite the request only being validly signed by `org-a`'s secret. [4](#0-3)

### Citations

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

**File:** lib/shipit.rb (L170-181)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
