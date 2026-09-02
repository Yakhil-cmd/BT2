## Finding

### Title
Webhook signature verification authenticates the payload's claimed organisation, not the repository/team it mutates — cross-tenant forgery via unsecured GitHub Apps - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate a request against using only `repository_owner` (`repository.owner.login`/`organization.login` taken from the *unverified* JSON body), then hands the same unverified body to handlers that act on a completely independent field — `repository.full_name` for `Handler#stacks`, or arbitrary `team.id`/`member.login` values for `MembershipHandler`. Because `GithubApp#verify_webhook_signature` treats a blank `webhook_secret` as automatically valid, any tenant organisation configured in Shipit's multi-org `secrets.yml` without a webhook secret (a documented, supported configuration) becomes an unauthenticated relay: an attacker can POST a self-crafted, unsigned payload naming that organisation and have handlers mutate state belonging to *any other* organisation/repository/team configured in the same Shipit instance.

### Finding Description
The controller resolves the signing organisation purely from attacker-suppliable JSON, before any signature has been verified: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` short-circuits to `true` whenever the resolved organisation has no `webhook_secret` configured: [3](#0-2) 

This is an explicitly supported configuration shape (`webhook_secret: # nil`), shown for every organisation in the multi-tenant example: [4](#0-3) 

Once past `verify_signature`, every handler consumes the same untrusted body but keys its side effects off **different fields than the one used to select the verifying secret**:

- `Handler#stacks` resolves the target `Repository`/`Stack` from `repository.full_name`, not from `repository.owner.login`: [5](#0-4) 

- `PushHandler` and `StatusHandler` then act on whatever stacks/commits that lookup returns, e.g. enqueuing a sync or writing a commit status: [6](#0-5) [7](#0-6) 

- `MembershipHandler` creates/updates a `Team` keyed by `team.id` (an arbitrary attacker-supplied GitHub team id) and adds/removes a `User` found purely by `member.login`, with no live cross-check against GitHub team membership: [8](#0-7) 

Since `User#authorized?` is computed solely from local `Team`/`Membership` rows against `Shipit.github_teams`: [9](#0-8) 

an attacker who can get *any* configured organisation to accept an unsigned request (i.e., one with a blank `webhook_secret`) can forge a `membership` event naming the `github_id` of a team that is actually one of `Shipit.github_teams`, and add an arbitrary `member.login` (their own GitHub username) to it — all without ever touching real GitHub team membership. `force_github_authentication` then grants that user access because `authorized?` only checks the local DB: [10](#0-9) 

The binding that should hold is: **organisation that authenticated the request == organisation/repository/team that is written**. Instead, the code enforces only "some configured organisation's secret matched (or none was required)" while the mutated resource identity is taken from unrelated, unverified fields in the same body — and Shipit is explicitly designed to host multiple independent organisations behind one instance (see `config/secrets.development.shopify.yml`), so a low-trust org config directly endangers all other tenants' repositories and access-control teams.

### Impact Explanation
This breaks cross-repository/cross-tenant isolation and can escalate into `Shipit.github_teams` authorization — both explicitly listed High-impact outcomes:
- Unauthorized writes to any stack/repository configured in the instance (spurious `GithubSyncJob` triggers, forged commit `Status` rows that can satisfy `ci.require`/merge-queue gating for a victim repository) via `PushHandler`/`StatusHandler`.
- Authentication/authorization bypass: an attacker can insert themselves (or any GitHub login) as a member of a `Team` used by `Shipit.github_teams`, thereby passing `current_user.authorized?` and gaining access to the whole Shipit UI/API for every repository it manages, without ever being a real member of that GitHub team.

### Likelihood Explanation
Exploitability depends only on one tenant organisation in the shared Shipit deployment lacking a `webhook_secret` — a state the engine itself treats as valid (`return true unless webhook_secret`) and that the sample multi-org configuration explicitly shows as commented-out/nil. No GitHub App private key, session, or `ApiClient` token is required; the attacker only needs network access to the `/webhooks` endpoint and knowledge of that organisation's name. Given Shipit's documented support for hosting many organisations from one instance, a single weakly configured tenant compromises the trust boundary for all others — a realistic, low-privilege condition.

### Recommendation
- Require `webhook_secret` to be present for every configured organisation; refuse to boot (or refuse all webhook processing for that org) if it is blank, rather than treating a missing secret as "verified."
- After signature verification, re-derive and cross-check the organisation actually referenced by the payload's `repository.owner.login`/`organization.login` against the organisation whose secret was used to verify the signature, and reject the request if they differ, in `WebhooksController#verify_signature` and in `Handler#stacks`/`MembershipHandler`.
- For `MembershipHandler`, do not trust `member.login`/`team.id` blindly; validate against a live GitHub API call scoped to the authenticated organisation before mutating `Team`/`Membership` records that feed `Shipit.github_teams` authorization.

### Proof of Concept
1. Deploy Shipit configured for two organisations, `orgA` (no `webhook_secret` set — a supported configuration) and `orgB` (has stacks and is a member of `Shipit.github_teams`).
2. As an unauthenticated attacker, `POST /webhooks/github` with header `X-Github-Event: membership` and a body: `{"action":"added","team":{"id":<github_id of orgB's authorizing team>,"name":"x","slug":"x","url":"https://x"},"organization":{"login":"orgA"},"member":{"login":"attacker"}}`. `WebhooksController#verify_signature` resolves `repository_owner` to `"orgA"`, whose blank `webhook_secret` makes `verify_webhook_signature` return `true` unconditionally — no valid `X-Hub-Signature` is needed.
3. `MembershipHandler#process` runs `Team.find_or_create_by!(github_id: params.team.id)` (matching orgB's real authorizing team by its GitHub id) and adds `User.find_or_create_by_login!('attacker')` as a member.
4. The attacker completes GitHub OAuth login as `attacker`; `current_user.authorized?` now returns true because the local `Membership` row exists, granting access to orgB's stacks despite never having been a real GitHub team member of orgB. [11](#0-10) [3](#0-2) [12](#0-11)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-47)
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
      end
    end
  end
end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
