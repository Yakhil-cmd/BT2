### Title
`membership` webhook lets an attacker who controls a foreign organization's webhook secret grant arbitrary GitHub users membership in any tracked `Team`, bypassing `Shipit.github_teams` authorization - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` authenticates an inbound GitHub webhook by reading `repository.owner.login`, falling back to `organization.login` only when no `repository` key is present. `MembershipHandler`, however, derives the `Team#organization` (and therefore which `Shipit.github_teams` a membership event affects) exclusively from the payload's `organization.login` field, never checking it against the field that was actually used to select the verifying secret. An attacker who legitimately controls one organization's webhook secret (a normal, documented multi-tenant configuration in this engine) can supply a `repository.owner.login` matching their own org (to pass signature verification) while setting `organization.login` to a victim organization, causing Shipit to add an arbitrary GitHub login to a `Team` belonging to that victim organization.

### Finding Description
The engine supports per-organization GitHub App configuration via `Shipit.github_app_config`, each with its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` picks the app (and therefore the secret) used to validate `X-Hub-Signature` by calling `repository_owner`, which reads `params.dig('repository','owner','login')` and falls back to `params.dig('organization','login')` only if no `repository` key is present: [2](#0-1) 

`MembershipHandler` declares its own schema requiring `organization.login`, `team`, and `member`, and uses `params.organization.login` (an independent read of the same raw payload) to create or find the `Team` and to add/remove members: [3](#0-2) 

Because `WebhooksController#create` parses the whole raw body once and hands the entire hash to every handler [4](#0-3) , an attacker can include an extra `repository` object solely to steer signature verification, while the actually-processed `organization` field used by `MembershipHandler` is a different value. The binding that should hold is:

`organization whose secret verified the request == organization written into Team#organization`

The code lets these diverge: verification is keyed off `repository.owner.login` (or `organization.login` only as a fallback), while `MembershipHandler` always uses `organization.login` regardless of what was used for verification.

### Impact Explanation
`Team#organization`/membership records populated this way feed directly into `Shipit.github_teams` and `User#authorized?`, which gates access to the entire Shipit instance [5](#0-4)  and [6](#0-5) . By forging a `membership` "added" event, an attacker who only controls their own organization's webhook secret can insert an arbitrary GitHub login as a member of a `Team` tied to a different, victim organization, potentially satisfying the team-membership check used to authorize access to stacks, deploys, and rollbacks in that victim's Shipit tenant. This matches the "escalation into `Shipit.github_teams` authorization" High-impact category.

### Likelihood Explanation
This requires the Shipit installation to be configured for more than one organization (a documented, supported feature — `TOP_LEVEL_GH_KEYS`/`github_app_config` in `lib/shipit.rb`), and requires the attacker to control (not steal) the webhook secret for at least one organization tracked by that same Shipit instance — plausible in any shared/multi-team Shipit deployment where different teams manage their own GitHub App installations pointed at a common Shipit host. No Shipit session, API token, or victim secret is needed.

### Recommendation
In `WebhooksController#verify_signature` and in every handler, derive the organization used to select the verifying `webhook_secret` and the organization used for any write (team creation, repository resolution, etc.) from the **same** payload field, and reject the webhook if `repository.owner.login` (when present) does not match `organization.login`. `MembershipHandler#find_or_create_team!` should validate that `params.organization.login` matches the organization that was used for signature verification before mutating `Team` membership.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (per `github_app_config`).
2. Attacker crafts a `membership` webhook body:
```json
{
  "action": "added",
  "team": {"id": 999, "name": "Attacker Team", "slug": "attacker-team", "url": "https://api.github.com/teams/999"},
  "organization": {"login": "victim-org"},
  "member": {"login": "attacker-login"},
  "repository": {"owner": {"login": "attacker-org"}}
}
```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s own (legitimately known) `webhook_secret` and sends the request with `X-Github-Event: membership`.
4. `verify_signature` resolves `repository_owner` to `"attacker-org"` (because `repository.owner.login` is present) and verifies successfully against `attacker-org`'s secret [7](#0-6) .
5. `MembershipHandler#process` runs using `params.organization.login == "victim-org"`, creating/finding a `Team` with `organization: "victim-org"` and adding `attacker-login` as a member [8](#0-7) .
6. If `victim-org`'s team is part of `Shipit.github_teams`, the attacker's GitHub login (after a normal OAuth login) now passes `current_user.authorized?` for the victim's Shipit tenant.

I could not fully trace which `secrets.github` structure a given production deployment uses (single-org vs. multi-org) since that is host-application configuration, not part of the engine's committed code — the vulnerability is conditioned on the documented multi-org `github_app_config` feature being enabled.

### Citations

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
