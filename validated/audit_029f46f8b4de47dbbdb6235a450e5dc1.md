### Title
Webhook Signature Verified Against `repository.owner.login`/`organization.login` While Handlers Act On Unverified `repository.full_name` — Cross-Organization Forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner` (`repository.owner.login`, falling back to `organization.login`). However, the event handlers that actually locate and mutate the `Stack`/`Repository` records use a completely different, unverified payload field: `repository.full_name`. Because these two fields are never cross-checked, a request signed with a legitimate secret belonging to Organization A can carry a `repository.full_name` pointing at Organization B's repository, letting the request act on Org B's stacks even though only Org A's key authorized the message.

### Finding Description
`verify_signature` computes the signing organization purely from the owner login (or `organization.login`) sub-object and fetches that org's `GithubApp` to validate `X-Hub-Signature`: [1](#0-0) [2](#0-1) 

Once the signature check passes, `create` dispatches the *entire* raw JSON payload to every registered handler for the event, unmodified: [3](#0-2) 

Handlers such as `PushHandler`, the `PullRequest` handlers, `StatusHandler` and `CheckSuiteHandler` never re-derive or validate `repository.owner.login`; instead they resolve the target `Repository`/`Stack` using `repository.full_name`, a separate JSON field that is not covered by the signature-selection logic: [4](#0-3) [5](#0-4) 

Nothing enforces that the organization component of `repository.full_name` matches `repository.owner.login`/`organization.login` used during signature verification. Shipit natively supports multiple independently-configured GitHub Apps/organizations, each with its own `webhook_secret` set by whoever installs the app for their org: [6](#0-5) [7](#0-6) 

This breaks the trust binding described by the rule set as: `organization that authenticated == repository that is written`. Before the (hypothetical) fix, `repository_owner (verified) != full_name.owner (acted upon)`; a correct implementation must enforce equality between the two.

### Impact Explanation
An entity that legitimately controls (or has been handed) the `webhook_secret` for **one** organization configured in a multi-org Shipit deployment can forge a valid signature for that organization while setting `repository.full_name` to any other organization's repository that already has a `Stack` in Shipit. This can:
- Trigger `GithubSyncJob`/`stack.sync_github` on an arbitrary target stack via forged `push` events, and post arbitrary commit `status` values (`StatusHandler`) that Shipit's CI-gating logic (`ci.require`, deploy gating) treats as trusted.
- Drive `pull_request` handlers to auto-provision Review Stacks (`ReviewStackAdapter#create!` → `ReviewStackProvisioningQueue.add`) or archive/unarchive stacks belonging to a repository the forging party has no legitimate authority over — i.e., cross-repository, cross-organization writes and unauthorized infrastructure provisioning.

This satisfies the "cross-repository writes / unauthorized deploy or provisioning" impact bar defined by the rules, without requiring a Shipit session, `ApiClient` token, or the *target* organization's secret — only knowledge of any one configured organization's own secret, which the rules explicitly recognize as a valid organization-vs-repository trust-boundary break.

### Likelihood Explanation
Any Shipit deployment configured for more than one GitHub organization (the documented and supported multi-tenant configuration, see `config/secrets.development.example.yml`) is exposed. Anyone who legitimately set up (or was given) the GitHub App/webhook secret for their own, smaller organization can immediately probe this path with a hand-crafted HTTP POST — no special access to the victim organization is required, and no code path anywhere cross-validates `repository.owner.login` against `repository.full_name`.

### Recommendation
In `WebhooksController`, after signature verification succeeds, derive the acted-upon organization from `repository.full_name` (or `organization.login` for org-scoped events) and assert it equals the organization used for signature verification (`repository_owner`); reject the request (422) on mismatch. Alternatively, centralize this check inside `Handler#repository_name`/`#stacks` so every handler enforces the invariant regardless of controller-level checks.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` (attacker-controlled, webhook secret `S_A` known to the attacker) and `org-b` (contains a real, deployed Shipit `Stack`), per `config/secrets.development.example.yml`.
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha, e.g. an old/malicious commit already in org-b's repo>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/target-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S_A, body)` using their own org's secret `S_A`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches `org-a`'s `GithubApp`, and the HMAC validates successfully.
6. `PushHandler` then resolves `repository_name` = `"org-b/target-repo"` via `Handler#repository_name`, finds `org-b`'s real `Stack`, and calls `stack.sync_github(expected_head_sha: "<attacker chosen sha>")` — an action on `org-b`'s stack authorized only by `org-a`'s credentials.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
