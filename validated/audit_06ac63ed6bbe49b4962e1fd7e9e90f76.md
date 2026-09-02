### Title
Webhook signature verification key is selected from an org field decoupled from the repository actually acted upon, allowing cross-organization spoofed events - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` chooses which GitHub App/webhook secret to validate a request against using `repository_owner`, a value read from the JSON body itself (`params.dig('repository', 'owner', 'login')`), while the event handlers that actually mutate state (e.g. `PushHandler`, the `pull_request` handlers) resolve the target `Repository`/`Stack` from a *different* field in the same attacker-supplied body: `repository.full_name`. Nothing binds these two fields together, so in a multi-organization Shipit deployment an attacker can pick an organization whose webhook secret is unset (a documented, supported configuration) to satisfy signature verification, while pointing `repository.full_name` at a repository belonging to a different, secured organization.

### Finding Description
`Shipit.github(organization:)` supports per-organization configuration, and `webhook_secret` is explicitly optional per organization: [1](#0-0) [2](#0-1) 

The controller resolves which app's secret to validate against purely from the JSON payload's `repository.owner.login` (or `organization.login`): [3](#0-2) [4](#0-3) 

`GitHubApp#verify_webhook_signature` intentionally accepts *any* signature (including none) when no secret is configured for the resolved organization: [5](#0-4) 

However, the handlers that actually process the event body never re-check that `repository.owner.login` matches the repository they operate on. They independently derive the target repository from `repository.full_name`: [6](#0-5) [7](#0-6) 

Because the controller only reads `params.dig('repository', 'owner', 'login')` to select the verification key, and the handlers only read `params.repository.full_name` to select the affected `Repository`, an attacker can submit a single JSON body where these two sub-fields disagree: `repository.owner.login` set to an org configured with no `webhook_secret` (satisfying `verify_signature`), and `repository.full_name` set to `"<secured-org>/<real-repo>"` (satisfying the handler's repository lookup). This breaks the intended binding: `organization that authenticated == repository that is written`.

### Impact Explanation
A successful forged request lets an unauthenticated attacker inject fabricated GitHub events (push notifications, commit statuses, pull_request state) against any repository/stack tracked by Shipit, as long as any one configured organization in the deployment has no `webhook_secret` set. This can:
- Trigger `GithubSyncJob` to resync a targeted stack based on attacker-controlled `expected_head_sha` (push events) - [8](#0-7)  - influencing which commits are considered deployable.
- Forge/alter pull-request state on a tracked repository's merge queue (labels/assignee/review-stack provisioning) via the `pull_request/*` handlers, which all resolve the affected repository purely from `full_name` - [9](#0-8) .
- Because these actions influence the merge queue and stack sync state used to gate deploys/merges, this can escalate to an unauthorized deploy/merge on a repository the attacker does not control, which meets the "unauthorized deploy/merge" bar for High/Critical impact defined in scope.

### Likelihood Explanation
Requires only that the Shipit deployment is configured with more than one GitHub organization (documented, supported feature) and that at least one configured organization has no `webhook_secret` set (also documented as optional per-org). No credentials, session, or GitHub write access are needed — only network access to the public `/webhooks` endpoint. This is a realistic operational configuration since `webhook_secret` is explicitly optional per the setup docs.

### Recommendation
Bind the signature-verification identity to the identity actually acted upon:
- In `WebhooksController#verify_signature`, after selecting `github_app` from `repository_owner`, also verify that `repository_owner` matches the owner encoded in `repository.full_name` (and in `organization.login` for org-scoped events) before dispatching to handlers.
- Alternatively, resolve the target `Repository` first, confirm its `owner` matches the app/organization whose secret validated the signature, and reject the request otherwise.
- Treat a missing `webhook_secret` for one organization as scoped strictly to that organization's own repositories, not as a blanket bypass usable to authorize payloads referencing other organizations' repositories.

### Proof of Concept
Assume a Shipit deployment configured with two organizations: `OrgOne` (has `webhook_secret` set) and `OrgTwo` (no `webhook_secret`, per `config/secrets.development.shopify.yml` pattern):
1. Attacker sends `POST /webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature`, with JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<forged-sha>",
  "repository": {
    "owner": { "login": "OrgTwo" },
    "full_name": "OrgOne/secured-repo"
  }
}
```
2. `WebhooksController#repository_owner` resolves to `"OrgTwo"` (`app/controllers/shipit/webhooks_controller.rb:59-62`), so `Shipit.github(organization: "OrgTwo")` is used.
3. `GitHubApp#verify_webhook_signature` returns `true` unconditionally because `OrgTwo` has no `webhook_secret` (`lib/shipit/github_app.rb:76-83`), regardless of the (missing/invalid) signature header.
4. `PushHandler#process` runs using `params.repository.full_name == "OrgOne/secured-repo"`, resolving and syncing the stack belonging to `OrgOne` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`), even though the attacker never satisfied `OrgOne`'s signature check. [10](#0-9) [5](#0-4) [7](#0-6)

### Citations

**File:** config/secrets.development.shopify.yml (L5-14)
```yaml
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L59-68)
```ruby
          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
