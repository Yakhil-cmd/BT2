### Title
Cross-organization webhook signature confusion allows unsigned push events to trigger `sync_github` on another org's stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` validates the request body from an attacker-controlled fallback field (`organization.login`) whenever `repository.owner.login` is absent from the payload, while the actual target stack is resolved later purely from `repository.full_name`. These two lookups are never required to reference the same organization, so a payload can be "authenticated" by one org's (unconfigured) secret while acting on a completely different org's repository/stack.

### Finding Description
The broken binding: **organization whose secret verified the bytes** (`repository_owner` → `Shipit.github(organization: repository_owner)`) must equal **organization owning the targeted repository/stack** (`payload.dig('repository','full_name').split('/').first`). The code never enforces this.

- `repository_owner` is computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  - it falls back to the top-level `organization.login` whenever `repository.owner.login` is missing, even if `repository.full_name` is present.
- `verify_signature` then does `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(...)`, allowing the request through if it returns `true` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that organization has no configured `webhook_secret`: `return true unless webhook_secret` [3](#0-2) .
- Once past `verify_signature`, `PushHandler#process` resolves the target stacks solely via `payload.dig('repository', 'full_name')` inside `Handler#repository_name`/`#stacks` [4](#0-3) , and calls `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on the matching branch [5](#0-4) .

Attacker request: a raw HTTP `POST /webhooks` (no session, no signature) with `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "full_name": "shopify/shipit-engine" },
  "organization": { "login": "attacker-org" }
}
```
Because `repository.owner.login` is omitted, `repository_owner` resolves to `"attacker-org"`. If `attacker-org` is a configured GitHub organization in Shipit's `secrets.github` but has no `webhook_secret` set, `verify_webhook_signature` returns `true` with no signature at all. The controller then dispatches to `PushHandler`, which looks up the stack for `shopify/shipit-engine` (via `repository.full_name`, unrelated to `attacker-org`) and calls `sync_github`, which (per existing test coverage) enqueues `GithubSyncJob` for that stack [6](#0-5) .

Why existing guards don't stop this: `drop_unhandled_event` only checks whether a handler exists for the event type, not organization binding [7](#0-6) ; `GithubOrganizationUnknown` rescue only fires if `attacker-org` isn't configured at all [8](#0-7) ; `ExplicitParameters` in `PushHandler` only validates presence of `ref`/`after`, not organization/owner consistency [9](#0-8) .

### Impact Explanation
A payload nominally "authenticated" against org A's (misconfigured/secret-less) GitHub App configuration can force a `sync_github` (which enqueues `GithubSyncJob`) against org B's real stack, with an attacker-chosen `expected_head_sha`. This is a forged-webhook authentication bypass and a cross-tenant stack mutation trigger, matching the Critical category ("a payload for one repository mutating another's stack"). It is repeatable against any repository/stack whose full_name the attacker knows, as long as one configured-but-secretless organization exists anywhere in the deployment's `secrets.github` multi-org config.

### Likelihood Explanation
This requires a specific precondition, explicitly given in the question: at least one organization configured in `Shipit.github_organizations` with no `webhook_secret` set (`@webhook_secret` nil). In a single-organization Shipit deployment (the common case, using `secrets.github` top-level keys, `github_default_organization` nil) this fallback logic is not reachable the same way, but in multi-org GitHub App deployments (`TOP_LEVEL_GH_KEYS` schema, one `GitHubApp` per org) it is plausible for an org to be onboarded without a `webhook_secret` yet (e.g. mid-setup). Attacker cost is trivial: one crafted unauthenticated HTTP POST, no secrets or credentials needed, fully repeatable.

### Recommendation
Bind the signature-verification organization to the same organization that will actually be acted upon: derive `repository_owner` strictly from `repository.full_name`/`repository.owner.login` when a `repository` object is present, and only use the top-level `organization.login` fallback when `repository` is completely absent from the payload (e.g., `membership`/`team` events). Additionally, `GitHubApp#verify_webhook_signature` should not silently return `true` when `webhook_secret` is blank in multi-org configurations — treat a missing secret for a configured org as a hard failure (422) rather than an automatic pass, or require every configured org to have a secret at boot time.

### Proof of Concept
Minitest (`ActionDispatch::IntegrationTest` or `ActionController::TestCase` matching existing `webhooks_controller_test.rb` style):
```ruby
test "cross-org push payload triggers sync on victim stack without valid signature" do
  # Precondition: configure 'attacker-org' with no webhook_secret, 'shopify' stack exists
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    Shipit::GitHubApp.new('attacker-org', { app_id: 1, installation_id: 1 }) # no webhook_secret
  )

  victim_stack = shipit_stacks(:shipit) # repository full_name == 'shopify/shipit-engine'

  request.headers['X-Github-Event'] = 'push'
  body = {
    ref: 'refs/heads/master',
    after: 'deadbeef',
    repository: { full_name: 'shopify/shipit-engine' }, # no owner.login
    organization: { login: 'attacker-org' }
  }.to_json

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: 'deadbeef']) do
    post :create, body:, as: :json  # no X-Hub-Signature header
  end
end
```
Both sides of the equality diverge and the exploit succeeds: `repository_owner` = `"attacker-org"` (used for signature check) vs. actual repository owner used for the stack lookup = `"shopify"` (from `full_name`) — they are not required to match, and `GithubSyncJob` is enqueued for the victim's real stack with no valid signature.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/controllers/shipit/webhooks_controller.rb (L39-49)
```ruby
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

**File:** lib/shipit/github_app.rb (L76-77)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L7-10)
```ruby
        params do
          requires :ref
          requires :after
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

**File:** test/controllers/webhooks_controller_test.rb (L23-32)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
    end
```
