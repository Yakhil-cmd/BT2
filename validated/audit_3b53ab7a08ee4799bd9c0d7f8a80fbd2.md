### Title
Webhook signature is verified against `repository.owner.login`'s organization secret, but handlers act on the unrelated `repository.full_name` field, allowing cross-organization/cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification from `repository.owner.login` in the JSON body, while every event `Handler` resolves the `Repository`/`Stack` it actually mutates from the independent `repository.full_name` field in the same body. Because the HMAC covers the raw payload verbatim, nothing forces these two fields to agree, so a valid signature computed with one organization's secret can carry a `repository.full_name` pointing at a totally different, unrelated repository.

### Finding Description
`verify_signature` derives the org used for signature checking purely from the payload itself: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` only checks that the raw body's HMAC matches the secret configured for that specific organization; it performs no validation of the body's content beyond the signature itself: [3](#0-2) [4](#0-3) 

Once the signature passes, every registered event `Handler` resolves the target `Repository` (and therefore the `Stack`s it will mutate) from a *different* field of the same payload, `repository.full_name`, with no cross-check against `repository.owner.login`: [5](#0-4) 

Concrete handlers such as `PushHandler` (queues `GithubSyncJob`/triggers a sync of an arbitrary SHA) and `CheckSuiteHandler` (schedules `RefreshCheckRunsJob`) operate purely on `stacks`, which is derived from that unauthenticated `repository.full_name`: [6](#0-5) [7](#0-6) 

Because Shipit supports multiple independently-configured GitHub Apps/organizations (each with its own `webhook_secret`, looked up by `organization` and raising `GithubOrganizationUnknown` when not found), an attacker who legitimately controls/administers **their own** organization's GitHub App (and therefore knows that org's `webhook_secret`) can craft a payload where `repository.owner.login` is set to their own org (so `verify_signature` picks and passes their own secret) but `repository.full_name` is set to `"victim-org/victim-repo"`. The signed payload is valid per `verify_webhook_signature`, yet the handlers act against the victim organization's `Stack`s.

**Binding broken:** organization that authenticated (`repository.owner.login` → secret used for HMAC) ≠ repository that is written (`repository.full_name` → `Repository.from_github_repo_name` → `Stack` mutated by the handler).

### Impact Explanation
This breaks a cross-repository trust boundary: an attacker with legitimate credentials for one tenant/organization on a shared Shipit instance can forge webhook events (`push`, `check_suite`, `status`, `pull_request`, `membership`) that are processed as if they originated from a completely different, unrelated organization/repository they do not control. Depending on the handler this can:
- force a resync of an arbitrary commit SHA into another org's stack (`PushHandler` → `GithubSyncJob`),
- forge commit/CI statuses via `StatusHandler` for another org's commits, which can gate deploy/merge eligibility elsewhere in Shipit,
- trigger check-run refreshes or provisioning/archival state changes on another org's review stacks.

This matches the Critical "cross-repository writes" / unauthorized-deploy category: actions are performed against a repository that never authorized the request.

### Likelihood Explanation
Requires the attacker to control a legitimately-configured organization/GitHub App on the same multi-tenant Shipit deployment (i.e., know their own org's `webhook_secret`) — no privileged access to the *victim* org or a Shipit session/API token is needed, satisfying the "unprivileged attacker" constraint relative to the target. Multi-organization configuration is a documented, supported engine feature (`Shipit.github(organization:)`, `GithubOrganizationUnknown`), so this doesn't depend on undocumented deployment behavior.

### Recommendation
In `WebhooksController#verify_signature`/`Handler#repository_name`, require that `repository.owner.login` (the field used to select the verifying `webhook_secret`) matches the owner segment of `repository.full_name` (the field used to resolve the target `Repository`), rejecting the webhook (422) on mismatch before dispatching to any handler.

### Proof of Concept
1. Attacker controls organization `attacker-org` on the shared Shipit instance and knows its GitHub App `webhook_secret` (legitimate admin of their own org's app settings).
2. Attacker crafts a `push` (or `check_suite`/`status`) payload body:
   ```json
   {
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
     "ref": "refs/heads/master",
     "after": "<arbitrary sha>"
   }
   ```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s `webhook_secret` over the exact raw body and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` (from `repository.owner.login`) and successfully verifies the signature.
5. `PushHandler#process` resolves `repository_name` as `victim-org/victim-repo` (from `repository.full_name`) and enqueues `GithubSyncJob` against `victim-org/victim-repo`'s stacks, even though that organization never authenticated this request.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class CheckSuiteHandler < Handler
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
        end
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
