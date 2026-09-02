### Title
Webhook signature verification keys off an attacker-controlled `repository.owner.login` field that is decoupled from the `repository.full_name` actually acted on, allowing forged GitHub events for any configured repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / HMAC secret to validate a webhook against using a field pulled directly out of the still-unverified JSON body, while every event handler acts on a *different* field of that same unverified body to decide which `Stack`/`Commit` to mutate. Because these two fields are never checked for consistency, and because `GitHubApp#verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for the selected organization, an attacker can pick whichever organization is unprotected (or whose secret they know) to authenticate the request, while pointing the payload's `repository.full_name` at a totally different, protected repository whose state gets mutated.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`:
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

`repository_owner` is read straight from `request.raw_post` (`params = JSON.parse(request.raw_post)`), which is entirely attacker-supplied at this point - the signature has not yet been validated. This organization value is used only to pick which app config (and therefore which `webhook_secret`) is used for HMAC verification:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

If verification passes (either because the selected organization has no `webhook_secret` configured, or the attacker actually knows that organization's secret), `create` dispatches the same raw `params` to every registered handler:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Every handler, however, resolves the target repository/stacks from a **different** field of the very same payload:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

Nothing enforces `repository.owner.login == repository.full_name.split('/').first`. Shipit explicitly supports multiple GitHub organizations, each with its own independent `webhook_secret`, `oauth`, and `app_id` (see `test/dummy/config/secrets_double_github_app.yml` and the "multiple Github applications" schema in `config/secrets.development.example.yml`) [5](#0-4) [6](#0-5) . This means an attacker can craft a single JSON body such as:
```json
{
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-or-unprotected-org" }
  },
  "sha": "...", "state": "success", ...
}
```
`verify_signature` will look up `Shipit.github(organization: "attacker-or-unprotected-org")`, and if that org's `webhook_secret` is blank/unset, `verify_webhook_signature` unconditionally returns `true` regardless of the actual `X-Hub-Signature` header - passing verification for a payload that will nonetheless drive `PushHandler`, `StatusHandler`, or `CheckSuiteHandler` against `victim-org/victim-repo`, a repository that belongs to a *different*, properly-secured organization.

This breaks exactly the binding the scan targets: **the organization that authenticated the webhook ≠ the repository that is actually written/acted upon.**

### Impact Explanation
This is a High-impact, unauthenticated-read/write-state issue reachable with no credentials:
- `StatusHandler#process` calls `commit.create_status_from_github!(params)` for any commit matching the forged `sha`, letting an attacker inject fabricated CI/status results (e.g., forcing green "success" statuses) on a target's commits without ever knowing the target org's real `webhook_secret` [7](#0-6) . Forged green statuses can factor into deploy-safety checks that gate whether Shipit permits a deploy.
- `PushHandler#process` triggers `stack.sync_github(expected_head_sha:)` on the victim stack for a forged `after` SHA [8](#0-7) .
- `CheckSuiteHandler#process` schedules `schedule_refresh_check_runs!` for arbitrary commits on the victim stack [9](#0-8) .

Because the mutation target (`repository.full_name`) is fully decoupled from the authentication key (`repository.owner.login`), this is a cross-repository/cross-organization write authorized by the "wrong" credential - i.e., an unauthorized action on a repository the attacker was never authenticated for.

### Likelihood Explanation
Exploitability depends on operator configuration: it requires (a) a multi-organization Shipit deployment (explicitly documented and supported), and (b) at least one configured organization with a blank/unset `webhook_secret`, or an organization whose secret the attacker has obtained through any other means (which then lets them forge events for *every other* org's repositories, not just their own). Given `webhook_secret` is explicitly optional per-organization (`webhook_secret: # nil` in every example config), this is a realistic misconfiguration, not a theoretical one; the vulnerable code path (mismatched fields feeding disjoint concerns) exists unconditionally in `app/controllers/shipit/webhooks_controller.rb` and `app/models/shipit/webhooks/handlers/handler.rb` regardless of configuration.

### Recommendation
- Derive the organization used for signature verification from the same field the handlers use to select the target repository (i.e., parse `repository.full_name` and use its owner segment for both the HMAC lookup and the stack lookup), so a single canonical value drives both decisions.
- Alternatively/additionally, after selecting `github_app` by `repository_owner`, assert that `repository_owner` matches the owner segment of `repository.full_name` before dispatching to handlers, rejecting the request (422) on mismatch.
- Consider making `webhook_secret` mandatory for every configured organization (fail closed on `nil`) instead of `verify_webhook_signature` returning `true` when unset.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgTwo` (attacker-known/no secret) and `victim-org` (has a real repository/stack and a real `webhook_secret`), mirroring `test/dummy/config/secrets_double_github_app.yml`.
2. POST to `/github/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "OrgTwo" }
  },
  "sha": "<real sha of a commit on victim-org/victim-repo>",
  "state": "success",
  "context": "ci/forged"
}
```
No `X-Hub-Signature` header (or an arbitrary one) is required, since `verify_signature` resolves `Shipit.github(organization: "OrgTwo")` whose `webhook_secret` is unset, so `verify_webhook_signature` returns `true` unconditionally (`app/controllers/shipit/webhooks_controller.rb:24-30`, `lib/shipit/github_app.rb:76-83`).
3. `WebhooksController#create` then dispatches to `StatusHandler`, which resolves `repository.full_name` (`victim-org/victim-repo`) via `Handler#repository_name`/`#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and creates a forged `Status` on the matching commit - despite the request never being authenticated against `victim-org`'s real webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
