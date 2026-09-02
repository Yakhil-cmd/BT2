Confirmed vulnerability: the webhook signature verification is keyed off `repository.owner.login`/`organization.login`, while every event handler resolves the target `Stack`/`Repository` by `repository.full_name`. These two fields are never cross-checked against each other.

### Title
Webhook signature verified against attacker-controlled organization while event is applied to a different repository's stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, which is read directly from the untrusted JSON payload (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). [1](#0-0) [2](#0-1)  However, once the signature check passes, every `Handler` resolves the repository/stack to act on using a *different* payload field, `repository.full_name`. [3](#0-2) [4](#0-3) 

### Finding Description
Shipit supports multi-organization GitHub App configuration, where `Shipit.github(organization: ...)` returns an app-specific `GitHubApp` instance holding a distinct `webhook_secret` per organization. [5](#0-4) [6](#0-5) 

The controller derives the *authenticating* organization purely from `repository.owner.login` (falling back to `organization.login`) taken from the raw JSON body the attacker controls: 
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

This is the field whose associated `webhook_secret` is used to `verify_webhook_signature`. [1](#0-0) 

But the field that determines *which repository/stack the event content is applied to* is `repository.full_name`, read independently in `Handler#repository_name` and in every concrete handler (e.g. `PushHandler`, `PullRequest::OpenedHandler#repository`). [3](#0-2) [7](#0-6) 

Nothing in the code enforces that `repository.owner.login` (the field the signature covers/selects the secret for) is consistent with `repository.full_name` (the field the handlers act on). An attacker who owns/installs their own GitHub App on their own organization (`attacker-org`) knows their own `webhook_secret` and can legitimately sign a payload with it. They can then set `repository.owner.login = "attacker-org"` (so `verify_signature` validates against the attacker's own known secret) while setting `repository.full_name = "victim-org/tracked-repo"` (so the handler resolves and acts on a `Stack` belonging to a completely different, tracked organization/repository). This breaks the equality that should hold: **organization that authenticated the payload == repository the payload is written to**. Handlers such as `PushHandler` (which enqueues `GithubSyncJob` for a stack), `PullRequest` handlers (which create/label/close review stacks), `commit_status`/`check_suite` handlers, etc. would then execute against the victim's `Stack` using attacker-forged data, without ever possessing the victim's real webhook secret.

### Impact Explanation
This allows an unprivileged attacker (who merely runs their own GitHub App/org, requiring no access to the victim's `webhook_secret`, `api_clients_secret`, or repository) to inject forged webhook events (pushes, pull request state, statuses, check-suite results, membership changes) against a stack they do not own, potentially triggering deploy-affecting side effects such as `GithubSyncJob`, review-stack creation, or commit-status manipulation that downstream deploy logic depends on. This crosses the "unauthenticated write into a tracked repository's stack state" boundary — an unauthorized action against a repository the attacker does not control, satisfying the High-severity "escalation" class described in scope (an unauthenticated actor manipulating stack/task state that should require GitHub-authenticated webhook delivery for that specific repository).

### Likelihood Explanation
Likelihood is high for any deployment where more than one GitHub organization/App is configured (the documented multi-org `secrets.yml` layout, [6](#0-5) ), since the attacker only needs to control one legitimate GitHub App installation (their own) to obtain a valid signature; no interaction with the victim organization is required. In single-organization deployments the impact is reduced because the same secret binds all repositories, but the fundamental confusion between the field used for authentication and the field used for authorization is still present in the code path.

### Recommendation
In `WebhooksController`, after successfully verifying the signature for `repository_owner`, also assert that the organization/owner embedded in `repository.full_name` (i.e., the owner segment of `full_name`) matches `repository_owner` before dispatching to handlers — or better, always derive both the signing key and the acted-upon repository from the same canonical field, and reject the webhook if they diverge.

### Proof of Concept
1. Attacker creates and installs their own GitHub App on `attacker-org`, obtaining `webhook_secret_attacker` (a legitimate, self-owned secret, requiring no access to the victim).
2. Attacker crafts a push webhook payload:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/tracked-repo"
  },
  "after": "<forged sha>"
}
```
3. Attacker computes `X-Hub-Signature` using `webhook_secret_attacker` and sets `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')`, whose `verify_webhook_signature` succeeds because the attacker signed with their own valid secret. [1](#0-0) 
5. `Shipit::Webhooks.for_event('push')` handlers run `PushHandler`, which resolves the stack via `Repository.from_github_repo_name('victim-org/tracked-repo')` [3](#0-2)  and enqueues a `GithubSyncJob` / processes the forged push data for the victim's tracked repository — despite the attacker never having possessed `victim-org`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
