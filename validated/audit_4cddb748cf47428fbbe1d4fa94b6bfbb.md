### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but event handlers act on the unrelated `repository.full_name` field — allowing cross-tenant webhook forgery ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports hosting multiple GitHub organizations under one installation, each with its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` selects which organization's secret to verify the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (or the fallback `organization.login`) [2](#0-1) . However, once the signature check passes, `Shipit::Webhooks.for_event(event)` dispatches the same raw JSON payload to handlers that identify the target `Repository`/`Stack` via an entirely different field — `payload.dig('repository', 'full_name')` — with no requirement that its owner matches the organization used for signature verification [3](#0-2) .

### Finding Description
The binding that should hold is: `organization authenticated == organization whose repository is acted upon`. Instead, the verified field (`repository.owner.login`/`organization.login`) and the acted-upon field (`repository.full_name`) are independent, attacker-controlled JSON keys inside the same raw payload body used to compute the signature.

An attacker who legitimately controls one tenant organization onboarded into this Shipit instance (i.e., they know that organization's `webhook_secret`, which is by design given to each org's own GitHub App admin) can craft a webhook payload where:
- `repository.owner.login` = `"attacker-org"` (used only to select the verification secret, and to satisfy `Shipit.github(organization: repository_owner)` [4](#0-3) )
- `repository.full_name` = `"victim-org/some-repo"` (used by every handler to resolve the actual `Repository`/`Stack` via `Repository.from_github_repo_name` [5](#0-4) )

They sign this payload with their own valid `attacker-org` webhook secret. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully validates the signature, because it only checks the HMAC against the secret for the organization named in the payload's owner field — not against the repository that will actually be mutated [6](#0-5) . The request then reaches handlers such as `PushHandler`, which resolves stacks purely from `repository.full_name` and triggers `stack.sync_github(expected_head_sha: params.after)` [7](#0-6) , or `PullRequest::ReopenedHandler`/`UnlabeledHandler`, which can `archive!`/`unarchive!` review stacks belonging to `victim-org` [8](#0-7) , or `StatusHandler`, which writes commit statuses for any commit matching the forged `sha` regardless of repository origin, since it doesn't even scope by repository [9](#0-8) .

### Impact Explanation
This crosses the exact boundary called out in scope: "an organization that authenticated versus the repository that is written." A tenant organization with a legitimately provisioned (but unprivileged relative to other tenants) GitHub App/webhook secret can forge GitHub events for repositories belonging to a completely different organization hosted on the same Shipit instance. Depending on the handler exercised, this can:
- Force out-of-band `sync_github`/deploy-triggering pushes against a victim repository's stacks (`PushHandler`).
- Archive/unarchive review stacks belonging to a victim repository (`ReopenedHandler`, `UnlabeledHandler`, `LabelCapturingHandler`).
- Inject arbitrary commit statuses for any commit hash across the whole installation (`StatusHandler`), which can influence merge/deploy eligibility checks.

This maps to "cross-repository writes" / "an unauthorized deploy, rollback or merge," meeting the High/Critical impact bar.

### Likelihood Explanation
Requires only that the attacker is a legitimate member/admin of one tenant organization already configured on the shared Shipit instance (a scenario explicitly documented as supported via the multi-org `github:` config block) [1](#0-0) . No GitHub App private key, `GITHUB_TOKEN`, or Shipit session/API token is needed — only the ability to send a POST to `/webhooks` with a payload signed with their own org's known webhook secret and a `X-Github-Event` header for a supported event. This is a realistic, low-effort attack for any multi-tenant Shipit deployment.

### Recommendation
After signature verification, re-derive the organization from `repository.full_name`'s owner segment (or `repository.owner.login`) and require they match; reject the request (422) if they don't. Alternatively, pass the verified `repository_owner` into `Webhooks.for_event(event).each { |handler| handler.call(params, verified_owner: repository_owner) }` and have `Handler#repository_name`/`#stacks` assert that `payload.dig('repository', 'owner', 'login')` used for lookup equals the value that was actually verified, so a single payload cannot mix an authenticated owner with a different acted-upon repository.

### Proof of Concept
```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1 of raw body, using attacker-org's known webhook_secret>
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "deadbeef...",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
1. `WebhooksController#repository_owner` returns `"attacker-org"` [10](#0-9) .
2. `Shipit.github(organization: "attacker-org")` loads attacker-org's config; `verify_webhook_signature` succeeds because the attacker signed with their own known secret [6](#0-5) .
3. `PushHandler` (dispatched for the `push` event) resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github` on all matching, non-archived stacks on the `master` branch — fully belonging to `victim-org`, an organization the attacker never authenticated against [7](#0-6) .

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
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
