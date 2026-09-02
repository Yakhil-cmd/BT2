### Title
Webhook signature verification is bypassed per-organization and decoupled from the repository field actually used to route the event, allowing cross-organization stack manipulation - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken directly from the untrusted, attacker-supplied JSON payload, and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that app's `webhook_secret` is blank. Every downstream event handler, however, resolves the actual target `Stack`/`Commit` using a *different* payload field (`repository.full_name`, or a bare `sha` with no repository scoping at all). This breaks the binding "the organization whose credential authenticated the request == the repository the request is allowed to act on."

### Finding Description
`verify_signature` picks the GitHub App/secret to verify against using a payload-controlled key: [1](#0-0) 

The lookup key (`repository_owner`) is read straight from the request body: [2](#0-1) 

`GitHubApp#verify_webhook_signature` treats a blank `webhook_secret` as "verification not required": [3](#0-2) 

Shipit explicitly supports multi-organization deployments where each organization gets its own independent `webhook_secret` entry, and the documented/shipped example configs leave `webhook_secret` commented out/`nil` by default: [4](#0-3) [5](#0-4) 

Once the request passes `verify_signature` (trivially, by naming an organization whose app config has no `webhook_secret`), the actual event handlers resolve the target `Stack` using a **separate** field of the same attacker-controlled payload — `repository.full_name` — with no cross-check that it belongs to the organization that was used for signature verification: [6](#0-5) [7](#0-6) 

`StatusHandler` is even weaker: it looks up commits globally by `sha` with no repository/organization scoping whatsoever, and creates a GitHub commit status record from fully attacker-controlled fields: [8](#0-7) 

Equality broken: `organization used to authenticate the webhook` (derived from `payload['repository']['owner']['login']`, matched against whichever org config happens to lack a `webhook_secret`) `!= repository/commit actually written to` (derived from `payload['repository']['full_name']` or a bare `sha`, with no relation enforced to the authenticating organization).

### Impact Explanation
An unprivileged, unauthenticated network attacker who can reach the `/github/webhooks` endpoint can forge events for **any** organization/repository tracked by Shipit as long as **any single organization** in the (documented, first-class) multi-org configuration has no `webhook_secret` set. This lets the attacker:
- Trigger `GithubSyncJob`/`sync_github` for arbitrary stacks belonging to a fully-secured organization via `PushHandler`.
- Inject fabricated commit statuses for any commit sha across any repository via `StatusHandler`, which can influence deployability/merge-queue gating checks (`Commit#create_status_from_github!`).
- Archive/unarchive review stacks or manipulate pull-request-driven provisioning via the `PullRequest::*Handler`s, using a forged `repository.full_name`.

This crosses the "escalation into unauthenticated read/manipulation of stack state" and potentially "unauthorized deploy/merge" impact bar described in the rules, since it lets an attacker who authenticated as nobody (or as a deliberately-unsecured org) act on a different, secured repository's stack state.

### Likelihood Explanation
Likelihood is contingent on operator misconfiguration (one org in a multi-org setup missing `webhook_secret`), but this is not a hypothetical edge case: it is the literal shipped default in `config/secrets.development.example.yml` and `config/secrets.development.shopify.yml` (`webhook_secret: # nil`), and the multi-org feature is documented as a supported, expected configuration in `docs/setup.md`. The root cause is a design flaw in `WebhooksController#verify_signature` / `GitHubApp#verify_webhook_signature`, not merely an operator error, because signature verification is decided per-organization while the target of the mutation is resolved from an entirely independent field of the same untrusted payload.

### Recommendation
- Do not let `verify_webhook_signature` silently succeed when `webhook_secret` is blank for the org resolved from the payload; if any org is misconfigured, reject the payload or require a global fallback secret.
- After signature verification, re-derive the acting organization from the GitHub App/installation context (not from the payload) and enforce that `repository.full_name`'s owner matches the organization whose secret verified the payload before invoking any handler.
- Scope `StatusHandler` (and any other handler) lookups by repository/organization, not solely by `sha`.

### Proof of Concept
1. Deploy Shipit with a multi-org config (per `docs/setup.md`), e.g. `OrgSecure` (has `webhook_secret: s3cr3t`) and `OrgOpen` (accidentally left `webhook_secret:` blank, matching the shipped example configs).
2. As an anonymous attacker, `POST /github/webhooks` with header `X-Github-Event: push` and a body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgOpen" },
    "full_name": "OrgSecure/some-real-repo"
  }
}
```
No valid `X-Hub-Signature` is required — `verify_signature` resolves `repository_owner` to `"OrgOpen"`, whose `GitHubApp#verify_webhook_signature` returns `true` unconditionally because its `webhook_secret` is blank (`app/controllers/shipit/webhooks_controller.rb:24-30`, `lib/shipit/github_app.rb:76-83`).
3. `PushHandler#process` then resolves stacks via `repository.full_name` = `"OrgSecure/some-real-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`), enqueueing `GithubSyncJob` for a stack that belongs to the fully-secured `OrgSecure` organization, without ever presenting a signature validated by `OrgSecure`'s actual `webhook_secret`.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
