### Title
`WebhooksController#verify_signature` authenticates the payload's `repository.owner.login` while event handlers act on the independent, unvalidated `repository.full_name` field, letting a webhook signed by one configured GitHub organization drive syncs/deploys for a stack belonging to a different organization's repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In a multi-organization Shipit deployment (`config/secrets.*.yml` supports a `github:` map keyed by organization [1](#0-0) ), the webhook signature is verified against the GitHub App/secret selected via `repository.owner.login` (falling back to `organization.login`) [2](#0-1) , but every event handler resolves the target repository/stack using the completely separate `repository.full_name` field of the same payload [3](#0-2) . These two fields are never cross-checked against each other, even though both are attacker-controlled content inside the JSON body that is only integrity-protected as a whole by an HMAC keyed to whichever organization `repository.owner.login` names.

### Finding Description
The binding that should hold is: `organization that authenticated (via HMAC secret keyed by repository.owner.login/organization.login) == repository that gets written to (repository.full_name used by handlers)`.

- `verify_signature` looks up the `GitHubApp` for `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (or `params.dig('organization', 'login')`), and calls `github_app.verify_webhook_signature(signature, raw_post)` [4](#0-3) [5](#0-4) .
- `verify_webhook_signature` HMAC-verifies the *entire raw body* against that organization's `webhook_secret` [6](#0-5) .
- Once verified, the whole raw body (including `repository.full_name`, `ref`, `after`, etc.) is handed unmodified to the handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [7](#0-6) .
- `Handler#stacks` and `Handler#repository_name` derive the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')` - a field that has no relationship whatsoever to `repository.owner.login` in the verification step [3](#0-2) .
- `PushHandler#process` uses that stack lookup to call `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on the matched branch [8](#0-7) , which enqueues `GithubSyncJob` [9](#0-8) .

Because the attacker fully controls the JSON body they send (and Shipit computes the HMAC over the raw body they provide), they can set `repository.owner.login` to an organization they legitimately administer in Shipit (so `Shipit.github(organization: ...)` resolves to a `GitHubApp` whose `webhook_secret` they know/control, since they configured that org's GitHub App webhook themselves) while setting `repository.full_name` to `"other-org/other-repo"` - a repository/stack belonging to a completely different organization also configured on the same Shipit instance. The signature check passes because it is scoped only to the owner org named in the payload; the handler then blindly trusts `repository.full_name` to pick which stack to act on.

### Impact Explanation
This breaks the deployment-trust binding between "the organization whose secret authenticated the webhook" and "the repository the webhook is actually applied to." A user who administers/owns just one GitHub organization connected to a shared Shipit instance can forge push events that:
- Trigger `GithubSyncJob` for stacks belonging to unrelated organizations/repositories, forcing unscheduled sync of commits and, for stacks with `continuous_deployment` enabled, potentially kicking off automatic deploys of already-existing commits (`Stack.schedule_continuous_delivery` / `ContinuousDeliveryJob` operate on stacks marked `continuous_deployment: true` once new commits are recorded) [10](#0-9) .
- Similarly affect `status`, `check_suite`, `pull_request`, and `membership` handlers, all of which key off `repository.full_name` from the same unvalidated payload [11](#0-10) , letting an org-A-controlled sender create/archive/unarchive review stacks or manipulate commit statuses/CI status for org B's repositories, and to create arbitrary `Team`/`User` records tied to org B (membership events are not scoped to a repository at all, only to the org used for signature verification, but push/status/pull_request handlers are the concrete case where the repository acted on diverges from the authenticating org).

This matches the "unauthorized deploy" / cross-repository-write class explicitly in scope, since a webhook cryptographically authenticated for organization A is able to cause writes/state changes and, in the continuous-deployment case, an unauthorized deploy for organization B's stack.

### Likelihood Explanation
Exploitability requires only that the attacker control (own/administer) at least one GitHub organization whose GitHub App is registered in this Shipit instance's `secrets.github` multi-org config - a routine, low-privilege scenario for any org in a multi-tenant Shipit deployment - and that another organization/stack also exists on the same instance (the documented multi-organization use case, see `config/secrets.development.shopify.yml`). No GitHub App private key, `api_clients_secret`, or session is needed; only the attacker's own org's `webhook_secret`, which they legitimately possess as the party who configured that org's GitHub App. The webhook endpoint is unauthenticated apart from this per-organization HMAC check.

### Recommendation
In `WebhooksController#verify_signature` / `Handler`, cross-validate that the organization used to select the verifying `GitHubApp`/secret matches the owner segment of `repository.full_name` (and of `organization.login` for org-level events) before dispatching to handlers; reject the webhook (422) if they diverge. Alternatively, key handler repository/stack lookups off the same verified `repository_owner` value rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Shipit is configured with two organizations in `secrets.github`: `attacker-org` (attacker administers the corresponding GitHub App and knows its `webhook_secret`) and `victim-org` (has a Stack with `continuous_deployment: true` tracking `victim-org/victim-repo`).
2. Attacker crafts a JSON push payload:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<sha that already exists in victim-repo, e.g. a stale/reverted commit>",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over the raw body and POSTs it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and verifies successfully against the attacker's own secret [12](#0-11) .
5. `PushHandler#process` resolves `stacks` from `repository.full_name = "victim-org/victim-repo"` [13](#0-12)  and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack, enqueuing `GithubSyncJob` and, given continuous deployment, an unauthorized deploy cycle for a repository the attacker does not control.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-63)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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
```

**File:** app/models/shipit/stack.rb (L129-133)
```ruby
    def self.schedule_continuous_delivery
      not_archived.where(continuous_deployment: true).find_each do |stack|
        ContinuousDeliveryJob.perform_later(stack)
      end
    end
```

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
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
