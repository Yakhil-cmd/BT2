Based on my investigation, I found a concrete analog: the webhook signature-verification step authenticates against an organization derived from an attacker-controlled field, while the actual mutating handler logic acts on a *different* attacker-controlled field (`repository.full_name`) that is never cross-checked against the field used for authentication.

### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while all handlers act on the unrelated, unverified `repository.full_name` field, allowing cross-organization forgery in multi-tenant GitHub App setups - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp`/webhook secret to validate the HMAC signature using `repository_owner`, computed as `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) [2](#0-1) . However, every registered webhook handler resolves the target `Repository`/`Stack` using a completely different field, `repository.full_name`, via `Handler#repository_name` and `Repository.from_github_repo_name` [3](#0-2) . `PushHandler`, the pull-request handlers, and others all key off `params.repository.full_name` to find the record they mutate [4](#0-3) [5](#0-4) .

Since Shipit supports multiple GitHub Apps configured per organization (`Shipit.github(organization:)`) with independent `webhook_secret`s [6](#0-5) , and `verify_webhook_signature` returns `true` unconditionally whenever an organization's `webhook_secret` is blank/nil [7](#0-6) , an attacker who controls (or can obtain webhook delivery from) any organization with no configured `webhook_secret` — or who otherwise knows that organization's secret — can craft a payload where `repository.owner.login`/`organization.login` names that low-security org (satisfying `verify_signature`), while `repository.full_name` names a completely different, legitimately-secured victim organization/repo. Because handlers never re-check that `full_name`'s owner matches the field used for authentication, the forged event is dispatched against the victim's `Stack`.

### Impact Explanation
This breaks the equality that should hold: `organization that authenticated == repository that is written`. In practice this lets an attacker (who need not have any relationship with the victim's GitHub org) trigger `GithubSyncJob` (drives which commits are considered deployable/mergeable) or pull-request state changes (e.g. `stack.unarchive!`, label capture, review-stack creation/archival) against a targeted Stack, without ever presenting the victim's actual webhook secret. This is an authentication-bypass class issue for cross-repository event injection, matching "unauthorized deploy/rollback/merge" surface since sync and merge-queue behavior (`ProcessMergeRequestsJob`) is driven by these webhook-updated records.

### Likelihood Explanation
Requires: (a) the Shipit installation to be configured with multiple GitHub organizations (the documented multi-org config format in `config/secrets.development.example.yml`/`docs/setup.md`), and (b) at least one configured organization having no `webhook_secret` set (also a documented, supported configuration — the `# nil` comment in the setup examples), or knowledge of any one org's secret. Since `webhook_secret` is explicitly documented as optional, this is a realistic misconfiguration that this code silently permits to become a cross-tenant authentication bypass rather than being confined to that one weakly-configured org.

### Recommendation
Verify the signature using the same identity that will actually be acted upon. Concretely, derive the authenticating organization from `repository.full_name`'s owner segment (or require it to match `repository.owner.login`/`organization.login` before proceeding), and reject the webhook if they diverge. Additionally, consider treating a blank `webhook_secret` as "verification required and failing" rather than "always verified", or at minimum log/alert distinctly when a payload's stated owner does not match the owner segment of `full_name`.

### Proof of Concept
1. Configure Shipit with two orgs: `victim-org` (has `webhook_secret: strongsecret`) and `attacker-org` (has `webhook_secret:` left blank, as the docs show is valid).
2. Attacker sends a `push` (or `pull_request`) webhook POST to `/webhooks` with:
   - `repository.owner.login` = `"attacker-org"`, `organization.login` = `"attacker-org"` (used only for signature routing)
   - `repository.full_name` = `"victim-org/victim-repo"` (used by the handler to find the real Stack)
   - No `X-Hub-Signature` value needed since `attacker-org` has no `webhook_secret`, causing `verify_webhook_signature` to return `true` unconditionally.
3. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and passes.
4. `create` re-parses the same raw body and dispatches to `PushHandler`/PR handlers, which resolve `Repository.from_github_repo_name("victim-org/victim-repo")` and mutate the victim's `Stack` (e.g., queue `GithubSyncJob`, unarchive a review stack) — despite the request never being authenticated under `victim-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
