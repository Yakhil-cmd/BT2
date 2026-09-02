### Title
Cross-repository status forgery via organization/repository binding confusion in webhook signature verification — ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate an incoming webhook's HMAC against solely from the payload's `repository.owner.login` (or `organization.login`) field, via `Shipit.github(organization: repository_owner)`: [1](#0-0) . In practice: [2](#0-1) 

`Shipit.github(organization:)` maintains a distinct `GithubApp`/webhook secret per configured organization, so a Shipit instance onboarding several teams/orgs has one legitimate webhook secret per org, each of which its own team can obtain (e.g. by configuring its GitHub App/webhook settings) — see `webhook_secret` handling per organization config in `GithubApp#initialize`/`#verify_webhook_signature`: [3](#0-2) [4](#0-3) 

Once the signature is validated for organization X, the controller dispatches the *entire, attacker-crafted payload* to the matching event handler: [5](#0-4) 

However, `StatusHandler#process` — which turns a webhook's `status` event into a real CI/CD status on a `Commit` — resolves the target `Commit` purely by `sha`, with **no check that the commit belongs to the same repository/organization that the signature was verified against**: [6](#0-5) 

Contrast this with `PushHandler`, which at least scopes to stacks resolved from `payload.dig('repository', 'full_name')` via `Handler#stacks`/`Handler#repository_name`: [7](#0-6) [8](#0-7) 

`StatusHandler` has no equivalent scoping. This breaks the binding: **organization that authenticated (via `repository.owner.login` used for HMAC verification) ≠ repository/commit that is actually written (any `Commit` row in the entire Shipit instance matching the attacker-chosen `sha`)**.

### Impact Explanation
An attacker who legitimately controls organization X (and therefore knows/derives X's configured webhook secret through X's own GitHub App/webhook settings, an unprivileged relationship to *other* stacks on the same shared Shipit instance) can:
1. Discover a commit SHA belonging to a *different* organization/repository Y's stack (commit SHAs are public via GitHub).
2. Send a `status` webhook whose `repository.owner.login`/`organization.login` = X (so `verify_signature` validates against X's own secret, which the attacker knows) but whose `sha`, `state`, `context`, `description`, `target_url` reference commit SHA belonging to Y.
3. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` globally, finds Y's commit, and calls `commit.create_status_from_github!(params)`, forging an arbitrary CI status (e.g. `state: "success"`, matching a `required`/`blocking` status context) on Y's commit.

Since Shipit gates deployability and continuous delivery on GitHub commit statuses (`required_statuses`, `blocking_statuses` in `DeploySpec`, referenced from `Stack`/`Commit#deployable?`), forging a passing status for a required CI check on a commit that never actually passed CI in the victim repository can make an otherwise non-deployable commit appear deployable, enabling an **unauthorized deploy** in organization Y — without the attacker ever having credentials, write access, or a session tied to Y.

### Likelihood Explanation
The precondition is realistic in a shared/multi-tenant Shipit deployment: any onboarded organization's legitimate webhook traffic (which the org itself configures and can therefore replicate) is sufficient to forge signed payloads that are dispatched instance-wide, since `StatusHandler` performs no per-repository/organization scoping when resolving the target `Commit`. No repository write access, session, or `ApiClient` token to the victim's stack is required — only the attacker's own, legitimately-configured webhook secret for their own onboarded organization.

### Recommendation
In `StatusHandler#process` (and any other handler resolving records purely by payload-supplied identifiers), verify that the resolved `Commit`'s stack/repository matches the `repository.full_name`/`repository.owner.login` used during signature verification (i.e., bind the two fields together and reject mismatches), consistent with the scoping already performed in `Handler#stacks`/`PushHandler`.

### Proof of Concept
1. Attacker controls organization `X`, onboarded to the shared Shipit instance, and knows `X`'s configured `webhook_secret` (as the org owner who set it up).
2. Attacker identifies a commit SHA `deadbeef...` belonging to organization `Y`'s stack (public on GitHub) which is pending a required status check `ci/tests`.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "X" } }
}
```
signed with `X`'s known `webhook_secret` (`X-Hub-Signature`).
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "X")` and verifies successfully, per [1](#0-0) .
5. `StatusHandler#process` finds `Y`'s commit by SHA and applies the forged `success` status, per [6](#0-5) , with no verification that the commit belongs to organization `X`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
