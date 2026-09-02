### Title
Cross-organization commit status forgery via unscoped `Commit.where(sha:)` lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub `status` webhook against the GitHub App/organization derived from the payload's `repository.owner.login` (falling back to `organization.login`), binding trust to "this payload was signed by organisation X's webhook secret." [1](#0-0)  However, once verified, `Shipit::Webhooks::Handlers::StatusHandler#process` never checks that the commit it mutates actually belongs to a stack/repository owned by that same authenticated organisation — it resolves target commits with a global, repository-unscoped query `Commit.where(sha: params.sha)`. [2](#0-1) 

### Finding Description
Every other handler in this directory scopes its side effects to the repository named in the payload via the shared `Handler#stacks` / `Handler#repository_name` helpers, which resolve `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before touching any records (see `PushHandler#process` calling `.stacks.not_archived.where(branch:)`). [3](#0-2) [4](#0-3) 

`StatusHandler`, by contrast, only requires `sha` and `state` from the payload and looks the commit up **globally across the entire `commits` table**, with no join/filter on `repository`, `stack`, or `organization`: [5](#0-4) 

This breaks the intended binding: **organisation authenticated (via `verify_webhook_signature` keyed by `repository_owner`) == repository/commit being written**. In a multi-tenant Shipit deployment (multiple `Shipit.github` organisations configured, as shown in `config/secrets.development.shopify.yml` / `test/dummy/config/secrets_double_github_app.yml`), an entity that legitimately controls a GitHub App installation for **Organisation A** (and therefore possesses a valid signature for A's webhook secret) can send a `status` event whose `sha` matches a commit belonging to a stack owned by **Organisation B**. The handler will happily call `commit.create_status_from_github!(params)` on that foreign commit, since the only equality checked is `sha`, not repository ownership. [2](#0-1) 

### Impact Explanation
Commit statuses are used by Shipit to determine whether a commit is "deployable"/mergeable; forging a passing status on a commit belonging to a different organisation's repository lets an org-A-scoped credential holder manufacture a fraudulent green check on org B's commit, potentially unblocking or triggering an unauthorized deploy/merge decision for a repository the attacker's organisation has no rights over. This is a cross-repository/cross-organization write achieved purely by exploiting an unscoped lookup — matching the "cross-repository writes / unauthorized deploy" High-impact category.

### Likelihood Explanation
Exploitation requires: (1) a multi-tenant Shipit install with more than one GitHub organisation configured (a documented, supported configuration per `config/secrets.development.shopify.yml`), and (2) a commit `sha` collision or foreknowledge between the attacker-controlled org's commit and the victim org's target commit (e.g., shared upstream/forked repositories, vendored code, or cherry-picked commits reproduced across orgs — a scenario not inherently rare given identical Git content hashes to the same SHA). Given the narrow, repo-scoped attacker capability required (their own org's genuine webhook secret) versus the wide, unscoped blast radius (any commit row in the database), likelihood is moderate, gated mainly on the SHA-collision precondition.

### Recommendation
Scope `StatusHandler#process` the same way every other handler does: require `repository.full_name` in the params, resolve the target `Stack`/`Repository` via `Repository.from_github_repo_name`, and filter `Commit.where(sha: params.sha, stack: stacks)` (or otherwise join to the repository) instead of querying `Commit` unscoped. This restores the invariant that the authenticated organisation can only mutate commits belonging to its own repositories.

### Proof of Concept
1. Deploy Shipit configured with two GitHub organisations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as supported by `Shipit.github(organization:)`). [6](#0-5) 
2. `OrgB` has a tracked commit with sha `abcdef...` in one of its stacks.
3. An actor with legitimate control of `OrgA`'s GitHub App (i.e., can produce a validly signed `status` webhook for OrgA) crafts and sends:
   ```
   POST /webhooks
   X-Github-Event: status
   X-Hub-Signature: sha1=<valid HMAC using OrgA's webhook_secret>
   {
     "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgA/some-repo"},
     "sha": "abcdef...",
     "state": "success"
   }
   ```
4. `WebhooksController#verify_signature` succeeds because the signature is valid for `OrgA`. [7](#0-6) 
5. `StatusHandler#process` runs `Commit.where(sha: "abcdef...")`, finds the `OrgB` commit (matching only by sha, ignoring that the authenticated payload's repository is `OrgA/some-repo`), and calls `create_status_from_github!`, writing a forged status onto `OrgB`'s commit. [2](#0-1)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
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
