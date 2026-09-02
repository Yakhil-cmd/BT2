### Title
Organization-Authenticated Webhook Signature vs. Organization-Acted-Upon Mismatch Allows Cross-Organization Team Membership Injection - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate an inbound webhook's HMAC using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` with a fallback to `params.dig('organization', 'login')`. `Webhooks::Handlers::MembershipHandler`, which processes `membership` events, instead reads a separate, independently-controlled field, `params.organization.login`, to decide which organization a `Team` belongs to, and matches/creates the `Team` row purely by the attacker-supplied numeric `params.team.id`. Because the same JSON body can carry a `repository.owner.login` that differs from `organization.login`, the organization whose secret authenticated the request is never checked against the organization the handler actually mutates.

### Finding Description
- Signature verification: [1](#0-0) [2](#0-1) 

`repository_owner` is computed by preferring `repository.owner.login` over `organization.login`. In a multi-organization Shipit deployment (a documented, supported configuration where each onboarded GitHub organization has its own `webhook_secret`), this lets a request be authenticated as coming from *any* onboarded organization whose secret the requester knows, purely by including a `repository.owner.login` key naming that organization.

- Handler logic operates on a completely different field: [3](#0-2) 

`MembershipHandler#find_or_create_team!` resolves the `Team` by `github_id: params.team.id` — an attacker-controlled integer in the payload, not derived from or checked against the organization that authenticated the request. If a `Team` record with that `github_id` already exists (created, e.g., via `bin/rake teams:fetch` or `Team.find_or_create_by_handle`, as documented in `docs/setup.md`), the existing record is reused and `team.add_member(User.find_or_create_by_login!(params.member.login))` adds an attacker-chosen GitHub login as a member — with no verification that the authenticating organization (`repository_owner`) matches `params.organization.login` or the target team's own `organization` column.

The broken binding, stated as an equality that the code should enforce but does not:
`organization_that_authenticated_the_HMAC (repository_owner) == organization_whose_team_membership_is_mutated (params.organization.login / team.organization)`

Before the attack: these two values happen to always coincide in genuine GitHub-issued webhooks, because GitHub always signs a payload for the org it actually describes. After the attacker's crafted request: the two values diverge — the HMAC is valid for organization A (attacker-administered), while the team mutated belongs to organization B (the actual protected Shipit tenant), because the code never cross-checks them.

### Impact Explanation
If the target `Team` row's `github_id` matches one of the teams configured in `Shipit.github_teams` (the config gating application access, see `app/controllers/concerns/shipit/authentication.rb` and `User#authorized?`), an attacker can add an arbitrary GitHub login as a member of that team purely by forging a webhook signed with a *different*, lower-trust organization's webhook secret. This is an escalation into `Shipit.github_teams` authorization — once that GitHub user subsequently authenticates via OAuth (`GithubAuthenticationController#callback` / `User.find_or_create_from_github`), `User#authorized?` succeeds because the injected membership matches a configured team ID, granting full access to the Shipit application: [4](#0-3) [5](#0-4) 

This directly matches the required High-severity category: "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Exploitation requires: (1) a multi-organization Shipit deployment (explicitly documented and supported), (2) attacker control of any one onboarded organization's webhook secret (e.g., being the admin of a lower-trust org that installed the same Shipit GitHub App — not requiring any privileged Shipit credential, ApiClient token, or the target org's own secret), and (3) knowledge of the target team's real numeric GitHub `github_id`, which is persisted in Shipit's DB and often derivable via GitHub's own team-listing API or from residual data (e.g., previously delivered legitimate membership webhooks). This is a realistic scenario for organizations that operate a shared Shipit instance across multiple GitHub orgs of differing trust levels, as the project's own docs recommend supporting.

### Recommendation
In `WebhooksController#verify_signature` and in `MembershipHandler` (and any other handler resolving organization/repository context), require that the organization used to select the webhook secret (`repository_owner`) matches the organization referenced by the event payload actually being acted upon (`params.organization.login`, or the repository's real owner for repo-scoped events) before processing. Additionally, `MembershipHandler` should scope its `Team` lookup by both `github_id` and the authenticated `organization`, rejecting membership mutations where the acted-upon organization differs from the one whose secret validated the signature.

### Proof of Concept
1. Configure Shipit (as documented) with two GitHub organizations, `attackerorg` (attacker-administered) and `realorg` (victim tenant, listed in `Shipit.github_teams`).
2. Look up `realorg`'s protected team's real GitHub `github_id` (e.g., via GitHub's team API or leaked webhook data).
3. Craft a JSON body:
```json
{
  "action": "added",
  "team": { "id": <realorg_admin_team_github_id>, "name": "Admins", "slug": "admins", "url": "https://api.github.com/..." },
  "organization": { "login": "realorg" },
  "member": { "login": "attacker-github-login" },
  "repository": { "owner": { "login": "attackerorg" } }
}
```
4. Sign the raw body with `attackerorg`'s `webhook_secret` (HMAC-SHA1), set `X-Github-Event: membership` and `X-Hub-Signature`.
5. POST to the Shipit webhooks endpoint. `verify_signature` resolves `repository_owner = "attackerorg"` and successfully validates using `attackerorg`'s secret.
6. `MembershipHandler#process` runs unchecked: it finds `realorg`'s existing `Team` (matched by `github_id`) and adds `attacker-github-login` as a member.
7. The attacker subsequently authenticates to Shipit via GitHub OAuth with `attacker-github-login`; `User#authorized?` now returns `true` because of the injected `Membership`, granting full Shipit access despite never being a real member of `realorg`'s team. [6](#0-5) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-64)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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
