### Title
Fail-open webhook signature verification allows unauthenticated escalation into `Shipit.github_teams` authorization - ([File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#create` is a public, unauthenticated route (`resources :webhooks, only: :create` in `config/routes.rb`) that dispatches raw JSON payloads to handlers, gated only by `GitHubApp#verify_webhook_signature`. That method fails open when no `webhook_secret` is configured for the organization resolved from the payload itself, allowing a fully unauthenticated attacker to forge `membership` webhook events that grant themselves membership in a `Shipit::Team` used for `Shipit.github_teams` authorization, bypassing GitHub's actual team membership entirely.

### Finding Description
`WebhooksController` runs no session/user authentication (it does not include `Shipit::Authentication`) and is reachable by anyone who can reach the app: [1](#0-0) 

The only gate is `verify_signature`, which resolves the GitHub App config purely from attacker-controlled payload fields (`repository.owner.login` / `organization.login`) and then asks that app's `verify_webhook_signature`: [2](#0-1) 

`GitHubApp#verify_webhook_signature` is fail-open: if `webhook_secret` is blank for that org/app configuration, it returns `true` unconditionally, and no cryptographic check is performed on any part of the payload: [3](#0-2) 

The `webhook_secret` field is documented and shipped as optional (`webhook_secret: # nil` in the example secrets files), so this is a supported, documented configuration state, not a misconfiguration of the host app: [4](#0-3) 

When verification is bypassed this way, `Shipit::Webhooks::Handlers::MembershipHandler#process` trusts the payload completely to mutate real `Team`/`Membership` records: [5](#0-4) 

It looks up an *existing* `Shipit::Team` purely by the attacker-supplied `team.id` (GitHub numeric team id) and, for `action == 'added'`, adds an attacker-controlled `member.login` to that team via `Team#add_member`: [6](#0-5) 

`User.find_or_create_by_login!` will create/fetch a `Shipit::User` for any login without validating that the login is actually a GitHub member of the target team; it merely fetches the public GitHub user profile: [7](#0-6) 

Finally, `User#authorized?`—the check that gates access to the entire Shipit UI via `Authentication#force_github_authentication`—relies solely on local `Membership` rows matching `Shipit.github_teams`: [8](#0-7) [9](#0-8) 

**Binding broken (as an equality):**
`organization/app whose configured webhook_secret authenticated the request` == `organization/app whose webhook_secret is actually verified`

is supposed to hold, but when `webhook_secret` is unset for the org resolved from the payload, the left side is vacuously "authenticated" (the check returns `true` with no secret at all), while the right side never verified anything — i.e., the binding "payload acted upon" vs "payload covered by a verified signature" collapses to nothing being verified. This is the direct analog of the HATS report's core defect: an entity (there, a Humanity ID; here, a `membership` event/team assignment) is acted upon by privileged application logic (`ccDischargeHumanity` / `MembershipHandler#process`) without the state genuinely being covered by the authentication mechanism meant to bind it (V1/V2 consistency check / HMAC signature check).

### Impact Explanation
This directly matches the listed High-severity impact "escalation into `Shipit.github_teams` authorization": an unprivileged, unauthenticated external attacker can add themselves (or any arbitrary login) to a `Shipit::Team` that gates access to the whole Shipit instance, without any GitHub App private key, webhook secret, Shipit session, or `ApiClient` token. Once "authorized," the attacker can access stack state, deploy history, and (depending on stack permissions) trigger deploys/rollbacks — a full authentication/authorization bypass of the app's team-based access control.

### Likelihood Explanation
Likelihood depends entirely on whether the deployment has configured a `webhook_secret` for the relevant GitHub App/organization. Since `webhook_secret` is explicitly documented and shipped as optional/nil in example configs (`config/secrets.development.example.yml`, `test/dummy/config/secrets_double_github_app.yml` shows `webhook_secret: # nil` for `OrgTwo`), this is a realistic, supported operating mode rather than a violation of documented setup. Any Shipit deployment that has not set `github.webhook_secret` is exploitable with a single unauthenticated HTTP POST.

### Recommendation
- Change `verify_webhook_signature` to fail closed: if `webhook_secret` is not configured, reject the webhook (or require `webhook_secret` to be mandatory in configuration/validation at boot).
- In `MembershipHandler`, cross-validate `organization.login` in the payload against the `Team#organization` already stored, and/or re-fetch team membership from the GitHub API rather than trusting webhook payload fields directly for authorization-relevant state changes.
- Consider requiring `github.webhook_secret` for any organization contributing to `Shipit.github_teams`.

### Proof of Concept
1. Target a Shipit deployment where the GitHub App for organization `acme` has no `webhook_secret` configured (a documented, supported configuration).
2. As an unauthenticated attacker, POST directly to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": <github_id_of_an_existing_shipit_team_used_in_Shipit.github_teams>, "name": "Developers", "slug": "developers", "url": "https://api.github.com/teams/1" },
  "organization": { "login": "acme" },
  "member": { "login": "attacker-github-login" }
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "acme").verify_webhook_signature(...)`, which returns `true` because `webhook_secret` is blank — no signature is required.
4. `MembershipHandler#process` runs, finds the existing `Team` by `github_id`, creates/loads a `User` for `attacker-github-login`, and calls `team.add_member(member)`, inserting a `Membership` row.
5. Attacker authenticates via the normal GitHub OAuth flow (`GithubAuthenticationController#callback`) with their real GitHub account `attacker-github-login`; `User#authorized?` now returns `true` because `teams.where(id: Shipit.github_teams.map(&:id)).exists?` matches the forged membership, granting full access to the Shipit UI despite never being a genuine member of the required GitHub team.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-16)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L6-34)
```ruby
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
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/models/shipit/user.rb (L22-28)
```ruby
    def self.find_or_create_by_login!(login)
      find_or_create_by!(login:) do |user|
        # Users are global, any app can be used
        # This will not work for users that only exist in an Enterprise install
        user.github_user = Shipit.github.api.user(login)
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
