### Title
Webhook signature is verified against `repository.owner.login`'s GitHub App while every event handler dispatches on the independent `repository.full_name` field, allowing spoofed events for a differently-configured organization to be attributed to any repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `GitHubApp` (and thus which `webhook_secret`) to use for HMAC verification based on `repository_owner`, read from `params.dig('repository','owner','login')` (falling back to `organization.login`). All downstream event handlers, however, resolve the actual repository/stack they act on from a completely different, unauthenticated field: `payload.dig('repository', 'full_name')`. These two fields are never checked for consistency, and the signature covers only the raw byte string against whatever secret was picked - it does not bind "the organization whose secret validated this request" to "the repository the handlers will act on."

### Finding Description
`verify_signature` in [1](#0-0)  computes:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is [2](#0-1) .

`Shipit.github(organization:)` looks up per-organization config, including `webhook_secret` [3](#0-2) , and `verify_webhook_signature` explicitly **returns true unconditionally when no `webhook_secret` is configured for that organization** [4](#0-3) .

Meanwhile, every webhook handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, the `PullRequest::*Handler`s) resolves the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')` via `Handler#repository_name`/`#stacks` [5](#0-4) , and `PushHandler#process` / `StatusHandler#process` / `CheckSuiteHandler#process` act on stacks matched purely by that field [6](#0-5) [7](#0-6) [8](#0-7) .

**Binding that should hold:** `organization whose secret verified the HMAC signature == organization that owns the repository the handler acts on`.

**Binding that actually holds:** the engine only checks `verify_webhook_signature(signature, raw_post)` against the app selected by `repository.owner.login`; it never confirms that `repository.owner.login == repository.full_name.split('/').first`, nor that the "verified" organization is the one the handler's `Repository.from_github_repo_name(full_name)` resolves to.

In a multi-organization Shipit installation (`config/secrets*.yml` supports multiple orgs, several fixtures show `webhook_secret: # nil` as a valid/documented configuration for an org, e.g. [9](#0-8) ), an attacker who knows (or can trivially satisfy, because it's unset) the webhook configuration of **any single onboarded organization with no `webhook_secret` set** can craft a POST to the public `/webhooks` endpoint (no CSRF protection, no authentication required - [10](#0-9) ) with:
- `repository.owner.login` = the org with no configured secret (so `verify_webhook_signature` short-circuits `true` regardless of the `X-Hub-Signature` header value), and
- `repository.full_name` = `"<victim-org>/<victim-repo>"` for a stack belonging to a *different*, properly-secured organization.

The request passes signature verification (because the check binds to the weak org) while the handler acts on the strong org's stack (because dispatch binds to `full_name`).

### Impact Explanation
This breaks the intended trust boundary that a webhook can only affect repositories belonging to the GitHub organization that cryptographically proved it sent the event. Concretely:
- `StatusHandler#process` ( [7](#0-6) ) lets the attacker inject a fabricated commit status (e.g., `state: "success"`) for any commit SHA in the victim's stack. Shipit uses commit statuses to gate whether a commit is `deployable?`/CI-passing before allowing deploys through the merge queue, so this can be used to make an otherwise CI-failing or unreviewed commit appear deployable, contributing to an unauthorized deploy.
- `PushHandler#process` and `CheckSuiteHandler#process` can trigger `GithubSyncJob`/`RefreshCheckRunsJob` for the victim's stack, which is a lower-severity forced state refresh but still an unintended cross-organization interaction triggered without the victim organization's credentials.

This matches the accepted High-severity impact class: escalation into authorization decisions that gate deploys, achieved without any credential belonging to the victim organization.

### Likelihood Explanation
The `/webhooks` endpoint is public and unauthenticated by design (it's meant to receive GitHub's webhooks), so reaching it requires no privileged access. The only prerequisite is that *some* onboarded organization in the Shipit instance has no `webhook_secret` configured — a state the engine's own configuration format explicitly allows and even ships as example/dev configuration (`webhook_secret: # nil`), and which is silently permitted rather than rejected by `verify_webhook_signature`'s `return true unless webhook_secret`. In any Shipit deployment that onboards more than one organization and does not uniformly enforce a `webhook_secret` for all of them, this is directly exploitable by an anonymous, unprivileged actor.

### Recommendation
- Reject webhook requests when the organization resolved for verification does not match the organization implied by every repository-identifying field in the payload used by handlers (i.e., cross-check `repository.owner.login` against `repository.full_name`'s owner segment before dispatch).
- Do not allow `verify_webhook_signature` to trivially return `true` when `webhook_secret` is blank in a multi-organization configuration; either require a secret for every organization or refuse to process events for organizations without one.
- Have `Handler#repository_name`/`#stacks` derive the target repository from the same organization identity that was cryptographically verified, rather than independently trusting `full_name` from the unauthenticated JSON body.

### Proof of Concept
1. Configure (or find in the wild) a Shipit instance with at least two organizations: `weak-org` (no `webhook_secret`) and `victim-org` (has stacks and a configured `webhook_secret`).
2. As an anonymous attacker, POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/tests",
  "repository": {
    "owner": { "login": "weak-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
No valid `X-Hub-Signature` is needed because `Shipit.github(organization: "weak-org").verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-83`).
3. `WebhooksController#create` dispatches to `StatusHandler`, which ignores `repository.owner.login` entirely and creates a `Status` on the matching `Commit` regardless of which stack/org owns it (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), forging a passing CI status for `victim-org/victim-repo` without ever presenting `victim-org`'s credentials.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-16)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

```

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
