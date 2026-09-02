### Title
Cross-organization webhook forgery via optional per-organization `webhook_secret` breaks the org-authenticated vs. repository-written binding, enabling forged commit statuses / pushes to any repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization used to validate the HMAC signature from `params.dig('repository', 'owner', 'login')` (or `organization.login`), which is a field taken from the **same attacker-supplied payload** that later determines which repository/stack the event handlers act on. [1](#0-0) 
Handlers, however, resolve the target repository independently from `payload.dig('repository', 'full_name')`. [2](#0-1) [3](#0-2) 

Because `webhook_secret` is documented and treated as optional per organization (`return true unless webhook_secret` unconditionally accepts the request when no secret is configured for that org), [4](#0-3) 
and Shipit explicitly supports multiple organizations each with independently configured (and independently optional) secrets, [5](#0-4) 
an unauthenticated network attacker can pick `repository.owner.login` = an organization that has no `webhook_secret` configured, causing `verify_signature` to pass with *any or no* signature, while setting `repository.full_name` = any other, fully protected organization/repository that the operator actually cares about.

### Finding Description
The binding that should hold is:
`organization authenticated by verify_signature == organization of the repository the handler subsequently writes to`

In `verify_signature`, the organization used to pick the `GithubApp`/secret is derived from the payload itself, not from any value verified against the request:
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
``` [6](#0-5) 

`verify_webhook_signature` unconditionally returns `true` if that organization's `webhook_secret` is blank:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 

All the setup docs and sample secrets configs mark `webhook_secret` as optional (`# nil`), including for multi-org deployments where separate orgs each carry their own (optionally empty) secret. [7](#0-6) [8](#0-7) 

After signature "verification," the actual handler dispatched by `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` resolves its target repository from a *different* payload field, `repository.full_name`, via `Handler#repository_name` / `Handler#stacks`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 
and similarly in `PullRequest::LabelCapturingHandler#repository`. [3](#0-2) 

Because `repository.owner.login` and `repository.full_name` are two independent, attacker-controlled fields in the same unauthenticated POST body, nothing enforces that the organization that "authenticated" the request (i.e., whose loose/absent secret let it through) is the same organization that owns the repository the handler subsequently mutates. An attacker only needs to know that *any* configured organization has no `webhook_secret` set — a common, documented, and low-friction configuration choice — to spoof events for a completely different, fully protected organization's repository.

Concretely, `StatusHandler`/commit-status handling (reachable via the same dispatch path) updates `Commit#add_status`, which can trigger `stack.schedule_merges` and emit `deployable_status`/`commit_status` hooks once a commit transitions to `success`/`pending`: [9](#0-8) 
and `Commit#deployable?` is defined purely from stored status state (`success? && !blocked?`), so a forged "success" status can make an otherwise-unvalidated commit `deployable?` and eligible for merge-queue processing. [10](#0-9) 
`PushHandler` similarly enqueues a GitHub sync for the resolved stack based purely on `repository.full_name` and `ref`/`after` from the payload. [11](#0-10) 

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary called out in scope. An attacker with no credentials, no Shipit session, and no `webhook_secret` for the *targeted* organization can forge webhook events (push, status, pull_request, membership, etc.) against a fully secured, unrelated stack, as long as any one organization configured in the multi-org `github:` block has an unset `webhook_secret` (explicitly supported and documented as the default/optional state). Effects include forging commit statuses that make arbitrary commits `deployable?` and trigger merge-queue processing (`stack.schedule_merges`), and spoofing pushes that trigger `GithubSyncJob` for a stack the attacker does not own — i.e., unauthorized manipulation of deploy/merge state on a repository the attacker has no relation to. This aligns with the in-scope "High" impact category ("escalation into authorization... or an unauthorized deploy/rollback/merge").

### Likelihood Explanation
Likelihood is high in any deployment using the documented multi-organization `github:` config pattern where at least one organization is left with `webhook_secret: nil` (shown as the example/default in `config/secrets.development.shopify.yml` and `config/secrets.development.example.yml`), which is a normal and encouraged configuration path, not a misconfiguration outside the documented setup. No attacker privileges, tokens, or secrets are required — only a POST to the public `/webhooks` endpoint with a crafted JSON body.

### Recommendation
Do not let the payload itself select which secret validates it. Either:
- Require `webhook_secret` to be configured for every organization (reject requests for orgs without one instead of treating it as "verified"), and/or
- After signature verification, re-derive/validate that `repository.full_name`'s owner matches the `repository_owner` that was used to select the verifying `GithubApp`, rejecting mismatches, and/or
- Bind the webhook delivery to a known repository (e.g., look up the `Repository`/`Stack` record and use its configured organization/secret) rather than trusting `repository.owner.login` from the unauthenticated body to select the verification key.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `orgA` (no `webhook_secret` set) and `orgB` (a real, secret-protected org with an active stack, e.g. `orgB/protected-repo`).
2. POST to `/webhooks` with `X-Github-Event: status` and any/garbage `X-Hub-Signature`, body:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/protected-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/attacker-forged",
  "branches": [{ "name": "main" }]
}
```
3. `verify_signature` calls `Shipit.github(organization: "orgA")`; `verify_webhook_signature` returns `true` immediately because `orgA` has no `webhook_secret`. [4](#0-3) 
4. The dispatched handler resolves the target repository via `payload.dig('repository', 'full_name')` = `"orgB/protected-repo"`, and updates the commit status for the victim's stack, potentially unblocking `deployable?`/merge-queue processing on `orgB`'s protected repository. [2](#0-1) [10](#0-9)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
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
