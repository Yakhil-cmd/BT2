### Title
Webhook organization used for signature verification is never bound to the repository the event mutates, allowing cross-organization webhook forgery when any configured GitHub App has no `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/secret to validate a webhook against using an attacker-controlled payload field (`repository.owner.login`), but every event `Handler` then resolves the `Stack`/`Repository` to mutate using a completely different, never-cross-checked payload field (`repository.full_name`). If a single configured organization in a multi-org Shipit install has no `webhook_secret` set (a state the shipped templates and docs explicitly allow), the trust binding "organization whose secret validated this request" == "repository this request is allowed to affect" is broken.

### Finding Description
`Shipit::WebhooksController` verifies the inbound webhook this way: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the JSON body and used to pick which `GitHubApp` (and therefore which `webhook_secret`) to verify against: [3](#0-2) 

Critically, `verify_webhook_signature` returns `true` unconditionally when that organization's `webhook_secret` is blank/unset (`return true unless webhook_secret`). This is a documented, supported configuration state — the shipped config templates ship with `webhook_secret:` left blank for one or more orgs: [4](#0-3) [5](#0-4) 

Once verification passes (trivially, for the org with no secret), `create` forwards the *entire* raw JSON payload to the registered handlers, unmodified and un-rescoped to the verified organization: [6](#0-5) 

Every handler then locates the target `Repository`/`Stack` purely from `repository.full_name` in that same payload — a field that was never tied to `repository.owner.login` (the field used for org/secret selection): [7](#0-6) [8](#0-7) 

Nothing in the request path re-validates that the repository named in `repository.full_name` actually belongs to the organization (`repository.owner.login`) whose secret authenticated the request. This is exactly the binding class called out for this scan: *"an organization that authenticated versus the repository that is written."*

### Impact Explanation
An unprivileged remote attacker who knows (or can discover, e.g. by probing/observing behavior) that any one organization configured on a shared/multi-tenant Shipit instance has an empty `webhook_secret` can send a crafted, unsigned HTTP POST to `/webhooks` with:
- `repository.owner.login` = the no-secret organization (so `verify_webhook_signature` trivially returns `true`)
- `repository.full_name` = any other, unrelated (and potentially far more sensitive) repository/stack tracked by the same Shipit instance
- `X-Github-Event` = `push`, `status`, or `check_suite`

This lets the attacker:
- Force a `GithubSyncJob` / `stack.sync_github` on an arbitrary stack (`PushHandler`), and
- Forge commit `Status` records for arbitrary commits (`StatusHandler`, referenced via the same repository-resolution pattern in `Handler#stacks`/`#repository_name`), which feed directly into `commit.deployable?` / `ci.require` checks that gate automatic and continuous deployment.

Because Shipit stacks with `continuous_deployment: true` and `ci.require` gating rely on these webhook-driven CI status/commit updates, an attacker able to forge them for a stack outside the organization that actually authenticated the request can influence deploy eligibility for that unrelated stack — i.e., contribute to an **unauthorized deploy**, one of the explicitly accepted High/Critical impacts for this scan.

### Likelihood Explanation
This requires no session, no `ApiClient` token, no `webhook_secret`, and no GitHub App private key — only that at least one organization among possibly many configured on the shared Shipit instance has no `webhook_secret` set, a state the project's own templates and setup docs treat as a normal, allowed configuration (blank `webhook_secret:` field). On any multi-org Shipit deployment where onboarding of a new/low-priority org hasn't yet had its webhook secret configured, this is directly reachable by an anonymous internet client with zero prior access.

### Recommendation
- Resolve the target `Repository`/`Stack` from the same organization that was used to select/verify the webhook secret, and reject (422) any event where `repository.owner.login` (or `organization.login`) does not match the repository actually resolved by `repository.full_name`.
- Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank in a multi-org configuration; require an explicit, audited opt-in (e.g., only allowed in `Rails.env.test?`/`development?`) rather than allowing it in production-shaped multi-tenant configs.

### Proof of Concept
1. Configure Shipit with two organizations: `org-a` (no `webhook_secret`) and `org-b` (has a `webhook_secret`, hosts a sensitive stack `org-b/prod-app` with `continuous_deployment: true`).
2. As an anonymous attacker, POST to `/webhooks` with header `X-Github-Event: status` and no/garbage `X-Hub-Signature`, and body:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/prod-app" },
  "sha": "<commit sha of org-b/prod-app>",
  "state": "success",
  "context": "ci/required-check",
  "branches": [{ "name": "main" }]
}
```
3. `verify_signature` calls `Shipit.github(organization: "org-a")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` and the request proceeds unauthenticated.
4. `StatusHandler` resolves the stack via `repository.full_name` = `org-b/prod-app` (per `Handler#stacks`/`#repository_name`) and records the forged `success` status for that commit, independent of `org-a`.
5. If `org-b/prod-app` has continuous deployment enabled and this was the last required CI check, the forged status can trigger an automatic, unauthorized deploy of `org-b/prod-app`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** config/secrets.development.shopify.yml (L5-18)
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
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
```

**File:** template.rb (L68-95)
```ruby
      github:
        domain: # defaults to github.com
        bot_login:
        app_id:
        installation_id:
        webhook_secret:
        private_key:
        oauth:
          id:
          secret:
          # team: MyOrg/developers # Enable this setting to restrict access to only the member of a team

    test:
      app_name: My Shipit
      secret_key_base: #{SecureRandom.hex(64)}
      host: 'http://localhost:4000'
      redis_url: redis://localhost
      github:
        domain: # defaults to github.com
        bot_login:
        app_id:
        installation_id:
        webhook_secret:
        private_key:
        oauth:
          id: <%= ENV['GITHUB_OAUTH_ID'] %>
          secret: <%= ENV['GITHUB_OAUTH_SECRET'] %>
          # teams: MyOrg/developers # Enable this setting to restrict access to only the member of a team
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
