### Title
Signature verification silently no-ops for organizations configured without a `webhook_secret`, letting an unauthenticated caller forge `membership` webhooks and self-grant `Shipit.github_teams` authorization - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as "nothing to check" and returns `true` unconditionally, and `WebhooksController#verify_signature` selects *which* app/secret to verify against using an unauthenticated field taken straight out of the request body itself. This mirrors the ERC777 class of bug: a guard (`depositCap` there, "is this webhook genuinely from GitHub" here) is checked against state/inputs that the caller fully controls, so the binding between "the organization GitHub authenticated the delivery for" and "the organization the engine treats the payload as coming from" can be broken by an attacker who simply mislabels the payload.

### Finding Description
`WebhooksController#verify_signature` looks up the app/secret to validate against using data taken from the *unauthenticated* JSON body: [1](#0-0) [2](#0-1) 

The HMAC check itself is implemented so that a missing/blank `webhook_secret` disables verification entirely, rather than failing closed: [3](#0-2) 

`webhook_secret` is explicitly documented and shipped as **optional** in every secrets template (`config/secrets.development.example.yml`, `docs/setup.md`, `test/dummy/config/secrets_double_github_app.yml`), all showing `webhook_secret: # nil`. For any organization configured this normal, documented way, `verify_webhook_signature` returns `true` for literally any payload, with any (or no) `X-Hub-Signature` header - the "verified organization" binding is never actually checked.

The `membership` webhook handler trusts the (now-unverified) payload to add an arbitrary GitHub login to a `Team`: [4](#0-3) 

Team membership is exactly the authorization gate used by `force_github_authentication`/`current_user.authorized?` to decide whether a logged-in GitHub user may use Shipit at all: [5](#0-4) 

So an attacker who (a) knows/controls a GitHub account and (b) knows that a given Shipit-integrated organization has no `webhook_secret` configured can `POST /webhooks` with `X-Github-Event: membership`, `action: added`, `organization.login` = that org, and `member.login` = their own GitHub username. `MembershipHandler#process` will create the `Membership`, and the attacker can then complete the normal GitHub OAuth login flow and pass `current_user.authorized?` even though they were never actually added to the team on GitHub. This breaks the binding "GitHub identity that GitHub's team API attests to" versus "the `Membership`/`Team` records the engine trusts for authorization."

### Impact Explanation
This escalates an otherwise-unprivileged external attacker into `Shipit.github_teams` authorization (High per the rubric), and can also be used to forge `push`/`status`/`check_suite` events for that organization's repositories, corrupting commit/status state that feeds into merge-queue and deploy decisions. The severity is bounded by requiring the target organization to have `webhook_secret` unset, which is a supported, documented configuration (not a misuse of the engine), and by requiring the attacker to know the organization is configured this way (observable only by probing, or by prior knowledge of a deployment).

### Likelihood Explanation
Moderate. `webhook_secret` being optional is explicitly presented as a normal setup choice in the docs ("Webhook secret (optional)"), so real-world deployments plausibly run without it. No credentials, tokens, or repository write access are needed - only knowledge that the target org's Shipit webhook has no secret and an unauthenticated HTTP POST to `/webhooks`.

### Recommendation
Fail closed instead of open: reject deliveries with `head(422)` when `webhook_secret` is blank/missing rather than treating an absent secret as "verification not required." At minimum, log/alarm loudly and disable authorization-sensitive handlers (e.g. `membership`) when no secret is configured, and require `webhook_secret` to be present for any `GitHubApp` whose `oauth_teams`/team-authorization is enabled.

### Proof of Concept
1. Configure (or target) a Shipit deployment where `github.<org>.webhook_secret` is left blank, as shown in `config/secrets.development.example.yml` and `docs/setup.md`.
2. As an unauthenticated attacker with any HTTP client, send:
```
POST /webhooks
X-Github-Event: membership

{
  "action": "added",
  "team": {"id": 48, "name": "Ouiche Cooks", "slug": "ouiche-cooks", "url": "https://example.com"},
  "organization": {"login": "<target-org>"},
  "member": {"login": "<attacker-github-login>"}
}
```
3. `verify_webhook_signature` returns `true` unconditionally (no secret configured), `MembershipHandler#process` runs and creates a `Membership` linking `<attacker-github-login>` to the team.
4. Attacker completes normal GitHub OAuth login as `<attacker-github-login>`; `current_user.authorized?` now succeeds because of the forged `Membership`, granting access to stacks/deploys gated by `Shipit.github_teams`. [6](#0-5) [3](#0-2) [7](#0-6)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
