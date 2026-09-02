## Title
Cross-organization commit-status forgery: webhook signature is verified against the payload's claimed `repository.owner`/`organization`, but `StatusHandler` writes to *any* commit matching `sha` regardless of that organization — ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to verify a webhook against using an organization name taken from the payload itself (`repository.owner.login` or `organization.login`), then, once verified, dispatches the *entire* raw payload to the matching event `Handler`. For the `status` event, `StatusHandler#process` never checks that the commit it mutates belongs to the organization/repository that was authenticated — it looks up `Commit.where(sha: params.sha)` engine-wide and calls `create_status_from_github!` on every match.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`:
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
``` [1](#0-0) 

The signature check is bound to `Shipit.github(organization: repository_owner)` — i.e. the webhook secret configured for *that organization* in the multi-org `github:` config block (see `config/secrets.development.example.yml`, which documents per-organization `webhook_secret` values). Shipit supports hosting multiple GitHub organizations, each with its own GitHub App / webhook secret. [2](#0-1) 

Once the signature is accepted, `WebhooksController#create` hands the *entire* JSON payload to `Shipit::Webhooks.for_event(event)` handlers, unmodified:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

`StatusHandler`, which handles the `status` event, then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

Note the base `Handler` class *does* provide a `repository_name`/`stacks` helper (`payload.dig('repository', 'full_name')`) used by other handlers such as `PushHandler`, but `StatusHandler` bypasses it entirely and matches purely on `sha` across the whole `Commit` table, with no scoping to the repository/organization that the signature check just approved. [5](#0-4) [6](#0-5) 

**The broken binding, as an equality:**
`organization authenticated by verify_signature (repository_owner claimed in payload)` ≠ `repository/commit actually written by StatusHandler (any Commit.sha match, engine-wide)`.

Because `repository_owner` is attacker-controlled (it's just a field read out of the same JSON body being sent), an operator of a legitimate, independently-installed GitHub App for **their own** organization "OrgA" (with its own valid `webhook_secret`, which they know because they configured it) can send Shipit a `status` webhook whose `repository.owner.login` is `"OrgA"` — passing signature verification with OrgA's own secret — while setting `sha` to a commit SHA that actually belongs to a completely different, unrelated stack/repository ("OrgB") tracked by the same Shipit instance. `StatusHandler` will happily create/update a commit status on that OrgB commit, because it never re-validates that the commit's repository matches the authenticated organization.

### Impact Explanation
This lets a party who is authenticated for one organization forge CI/commit statuses (e.g. flip a required check to `success`) on commits belonging to a completely different organization's repositories hosted on the same Shipit instance. If deploy safety gates (`Stack#allow_pending_github_checks`, required statuses on deployable commits, etc.) rely on `Commit` statuses, this is a path to influencing/unblocking deploy eligibility for repositories the attacker has no legitimate write access to — an authorization boundary bypass between organizations that Shipit is supposed to keep isolated by binding webhook verification to `repository_owner`. This matches the "High: escalation ... unauthenticated read/write of stack state" and borders on "unauthorized deploy" impact classes, since falsified commit statuses can directly affect what is considered deployable.

### Likelihood Explanation
Requires the deployment to be configured for multiple organizations (the `github:` multi-org config format Shipit explicitly documents/supports) and requires the attacker to control a legitimate GitHub App/webhook secret for *at least one* of those organizations — a low bar, since that's exactly the trust model Shipit's own docs describe as normal multi-tenant usage. No repository write access, `ApiClient` token, or session is needed; only the ability to send an HTTP POST to `/webhooks` with a validly-signed-for-their-own-org payload.

### Recommendation
`StatusHandler` (and any other handler that doesn't already scope by `repository_name`/`stacks`) must verify that the `Commit` records being mutated belong to the repository named in `payload.dig('repository', 'full_name')`, and that repository's owner must match the `repository_owner` used to select the verifying `webhook_secret`. Concretely, scope the lookup as `Commit.where(sha: params.sha, stack: Repository.from_github_repo_name(repository_name)&.stacks)` (mirroring the `Handler#stacks` helper), instead of an unscoped `Commit.where(sha: ...)` across all repositories.

### Proof of Concept
1. Configure Shipit with two organizations in `github:` config, `OrgA` and `OrgB`, each with a distinct `webhook_secret`, both onboarded onto the same Shipit instance (as documented in `config/secrets.development.example.yml`).
2. As the operator of `OrgA`'s GitHub App (a party with no access to `OrgB`), craft a `status` event payload:
```json
{
  "sha": "<sha of a commit belonging to an OrgB-owned repository/stack>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/some-repo" }
}
```
3. Sign the payload body with `OrgA`'s own `webhook_secret` and send it to `POST /webhooks` with header `X-Github-Event: status`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and successfully verifies the signature against `OrgA`'s secret.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, finds the OrgB commit purely by SHA match, and calls `create_status_from_github!`, writing a forged `success` status onto a commit the attacker has no legitimate relationship to, in an organization they don't operate.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
