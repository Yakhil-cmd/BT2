### Title
Webhook signature is verified against the organization named in the payload, but handlers act on unrelated payload fields not covered by that authorization scope - cross-organization forgery of commit statuses and team memberships (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based solely on `repository.owner.login` (or `organization.login`) pulled from the *untrusted* JSON body, then verifies the raw body against that org's secret. [1](#0-0)  Once verification succeeds, the individual `Handlers::Handler` subclasses act on *other* fields of the same payload - `repository.full_name` for stack lookup, `params.sha` for status matching, `organization.login` for team creation - which are never independently validated against the organization whose secret produced the signature. [2](#0-1) [3](#0-2) [4](#0-3) 

This is the same bug class as the M-2 report: a piece of global/shared state (here, "which org this signed request is authorized to act for") is updated/consumed using one field, while a *different*, unchecked field is what downstream logic actually operates on - breaking the intended binding between the authenticated principal and the resource acted upon.

### Finding Description
Shipit supports multiple GitHub organizations, each configured with its own `webhook_secret` in `Shipit.github(organization:)` config. [5](#0-4)  The webhook endpoint is unauthenticated (no session or API token required) and dispatches purely based on the `X-Github-Event` header and JSON body: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [6](#0-5) 

The equality that should hold is:
`organization whose secret validated the HMAC == organization/repository the handler mutates`

But `repository_owner` (used to pick the verification secret) is read from `params.dig('repository', 'owner', 'login')` or the top-level `organization.login`, [7](#0-6)  while:
- `PushHandler`/`Handler#stacks` resolves the target `Repository` from `payload.dig('repository', 'full_name')`, [2](#0-1) 
- `StatusHandler#process` does not scope by repository at all - it matches **any** `Commit` in the entire installation by `sha` and writes a fake CI/build status onto it: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, [3](#0-2) 
- `MembershipHandler#process` creates/updates a `Team` using the `organization` field taken from the body (`params.organization.login`) and adds/removes arbitrary GitHub logins as members of that team. [8](#0-7) 

An operator who legitimately owns one configured GitHub App/organization (e.g. `someothergithuborg` in the multi-org config) knows that org's real `webhook_secret`. [9](#0-8)  That operator can craft a JSON payload where `repository.owner.login` (or `organization.login`) is their own org - so `verify_signature` picks their own secret and the HMAC passes - but where the operative field(s) (`repository.full_name`, `sha`, or `organization.login` used deeper in processing) reference a completely different, victim organization's stacks, commits, or teams. Because the handler never re-checks that these fields belong to the same org that was cryptographically authorized, the forged event is processed as if it legitimately originated from the victim org's GitHub App.

### Impact Explanation
- Via `StatusHandler`, an attacker with legitimate access to any one configured org's webhook secret can inject arbitrary commit statuses (`success`/`failure`, arbitrary `context`/`description`/`target_url`) onto commits belonging to a victim repository/organization, since the lookup is a global, unscoped `Commit.where(sha: ...)`. [3](#0-2)  Shipit deploy/merge gating relies on commit statuses (deployable/merge status), so this can be used to fabricate a passing CI status and enable an unauthorized deploy or merge of a commit that never actually passed checks - a Critical impact per the program's own criteria ("unauthorized deploy, rollback or merge").
- Via `MembershipHandler`, the attacker can create/mutate `Team` records and add arbitrary GitHub logins to teams, using an `organization.login` value that is unrelated to the org that produced the valid signature. [10](#0-9)  If that team is later referenced in `Shipit.github_teams` (the set that gates `User#authorized?`), this constitutes escalation into `Shipit.github_teams` authorization - explicitly listed as a High-severity impact. [11](#0-10) 
- Via `PushHandler`, forged `push` events can trigger `GithubSyncJob`/`sync_github` on a victim repository's stacks with an attacker-chosen `expected_head_sha`. [12](#0-11) 

### Likelihood Explanation
Requires the attacker to legitimately control one configured GitHub organization's webhook secret in a Shipit deployment that hosts multiple organizations (a supported, documented configuration [5](#0-4) ). No Shipit session, `ApiClient` token, or repository write access to the victim org is needed - only the ability to POST to the public `/webhooks` endpoint with a crafted body and a valid HMAC computed from a secret the attacker already legitimately possesses. This matches the "unprivileged attacker breaking a deployment-trust binding" class explicitly targeted by the review.

### Recommendation
After `verify_signature` succeeds, thread the authorized `repository_owner`/organization through to each handler and have handlers assert that every organization/repository-bearing field they act on (`repository.full_name`, `organization.login`, and for `StatusHandler`, the commit's owning repository) belongs to that same authorized organization before mutating any records. For `StatusHandler` specifically, scope the `Commit` lookup by the verified repository rather than a bare `sha` match across all repositories.

### Proof of Concept
1. Deploy Shipit configured with two GitHub orgs: `attacker-org` (attacker is the GitHub App/webhook secret owner) and `victim-org` (hosts a Shipit stack the attacker has no access to), as supported by `config/secrets.*.yml`. [5](#0-4) 
2. Attacker crafts a `status` event JSON body:
   ```json
   {
     "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/whatever"},
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/forged",
     "created_at": "2026-09-01T00:00:00Z"
   }
   ```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s real `webhook_secret` and sends `POST /webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s webhook secret, and the HMAC check passes. [13](#0-12) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim commit regardless of which org actually owns it — and writes the forged "success" status onto it. [3](#0-2) 
6. If `victim-org`'s deploy/merge flow gates on this status, the forged status can be leveraged toward an unauthorized deploy/merge.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-43)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandler < Handler
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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
