### Title
Signature verification keys on `repository.owner.login` while webhook handlers act on `repository.full_name`, allowing an org with no `webhook_secret` to forge writes against any other repository's stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to validate the inbound HMAC against using `repository_owner`, a field parsed straight out of the unauthenticated JSON body (`repository.owner.login`, falling back to `organization.login`). [1](#0-0)  Every downstream event handler, however, resolves the `Repository`/`Stack` to act on using a *different* field of the same body — `repository.full_name` — via `Handler#repository_name`/`#stacks`. [2](#0-1)  Nothing ties `repository.owner.login` to the owner segment of `repository.full_name`. Because Shipit explicitly supports per-organization `webhook_secret` configuration (including leaving it blank/`nil` for a given org) [3](#0-2) , and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when no secret is configured [4](#0-3) , an unauthenticated attacker can pick any org that has no `webhook_secret` set, put that org's name in `repository.owner.login` (or `organization.login`) to sail through `verify_signature`, and then set `repository.full_name` to any other, fully-secured org/repo hosted on the same Shipit instance. The handlers act on that forged `full_name` value with no further check against the "authenticated" organization.

### Finding Description
- `verify_signature` derives the authorizing organization purely from attacker-controlled JSON:
`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [5](#0-4) 
- It uses that value to fetch a `GitHubApp` (`Shipit.github(organization: repository_owner)`) and calls `verify_webhook_signature` on it. [6](#0-5) 
- `GitHubApp#verify_webhook_signature` trivially passes when the org's `webhook_secret` is blank: `return true unless webhook_secret`. [4](#0-3) 
- Once past that gate, `WebhooksController#create` dispatches the *entire raw payload* to the registered handlers for the event type, unmodified. [7](#0-6) 
- Every default handler (push, status, pull_request variants) looks up the target `Repository`/`Stack` via `payload.dig('repository', 'full_name')`, not `repository.owner.login`: [8](#0-7)  e.g. `PushHandler#process` calls `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }` where `stacks` resolves via that `full_name`. [9](#0-8) 

This is exactly the "organization that authenticated versus the repository that is written" binding break: the value used to select/pass the cryptographic gate (`repository.owner.login`) is disjoint from the value that determines which stack's data gets mutated (`repository.full_name`). The HMAC signature, when present and enforced, would cover the whole body and thus would normally bind these two fields together implicitly — but that protection is voidable per-organization simply by that organization having no `webhook_secret` configured, which is a documented, supported configuration state (`webhook_secret: # nil` appears in the shipped example secrets templates). [10](#0-9) 

### Impact Explanation
Any Shipit deployment hosting multiple GitHub organizations/apps (a documented, supported configuration, see `docs/setup.md` "Using Multiple Github Applications") is only as strong as its weakest org's webhook secret. If a single org in that install has no `webhook_secret` (nil is an explicitly valid value accepted by `GitHubApp#verify_webhook_signature`), an unauthenticated internet attacker can:
- Forge `push` events naming any other org/repo's stack in `repository.full_name`, forcing `GithubSyncJob` runs and cache-spec rebuilds on stacks they have no access to.
- Forge `status` events to inject fabricated commit statuses against arbitrary commits/stacks belonging to a different, fully-protected organization, potentially satisfying CI requirements that gate the merge queue (`MergeRequest#all_status_checks_passed?`) and deploy safety checks, which can translate into an unauthorized merge/deploy for a repository the attacker never had access to — this matches the "cross-repository writes / unauthorized deploy, rollback or merge" High/Critical impact bucket.
- Forge `pull_request`/`membership` events referencing arbitrary `full_name`/teams to alter review-stack provisioning or archive/unarchive stacks belonging to unrelated orgs.

This requires no session, no `ApiClient` token, no GitHub write access, and no TLS interception — only knowledge that a given multi-org Shipit install has at least one org configured without a webhook secret, which is visible from public documentation defaults and common operational neglect (nil secret is the shipped example default).

### Likelihood Explanation
Likelihood depends entirely on deployment configuration: it requires (a) a multi-org Shipit install, and (b) at least one of those orgs having `webhook_secret` unset. Both conditions are explicitly supported and even shown as defaults in the shipped example config files, making misconfiguration plausible in real-world setups that add a "low-risk" or internal org without bothering to set a webhook secret, while other orgs are hardened. Given the shipped templates literally show `webhook_secret: # nil` as the baseline, this is a realistic, not purely theoretical, configuration mistake that the engine does nothing to prevent or warn about.

### Recommendation
- Do not let `verify_webhook_signature` return `true` when `webhook_secret` is blank in a multi-organization configuration; either require a secret for every configured organization or refuse to process events for organizations without one.
- Bind the field used for signature/organization resolution to the field handlers actually act on: after selecting the signing organization from `repository.owner.login`/`organization.login`, validate that the owner segment of `repository.full_name` matches that same organization before dispatching to handlers, rejecting mismatches with a 422.
- Consider deriving the org used for verification the same way handlers derive the acted-upon repository (i.e., from `repository.full_name`'s owner segment) so a single field always governs both authentication and effect.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgA` (no `webhook_secret` set) and `OrgB` (has a `webhook_secret` and a protected stack, e.g. `orgb/critical-repo`), per the documented multi-org config format. [3](#0-2) 
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "orgb/critical-repo" },
  "organization": { "login": "OrgA" },
  "sha": "<target commit sha in orgb/critical-repo>",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "http://attacker.example",
  "created_at": "2026-09-01T00:00:00Z"
}
```
No `X-Hub-Signature` header (or any value) is required, because `verify_signature` resolves `GitHubApp` for `OrgA`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally. [4](#0-3) 
3. `Shipit::Webhooks::Handlers::StatusHandler` (registered for the `status` event) processes the payload using `repository.full_name` = `orgb/critical-repo`, writing/replicating a forged "success" status onto the commit belonging to `OrgB`'s protected stack — an organization the attacker never authenticated against.
4. If that context is a required CI status for `orgb/critical-repo`'s merge queue or deploy gating, this forged status can allow an unauthorized merge or deploy on a repository/organization the attacker has no legitimate access to.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
end
```

**File:** config/secrets.development.example.yml (L1-38)
```yaml
host: 'localhost:3000'
redis_url: 'redis://127.0.0.1:6379/0'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app
# Can be obtained there: https://github.com/settings/apps
# Set the "Authorization callback URL" as `<host>/github/auth/github/callback`

github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional

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
