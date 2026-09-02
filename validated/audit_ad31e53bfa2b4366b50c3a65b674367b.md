### Title
Unauthenticated webhook forgery grants `Shipit.github_teams` authorization when `webhook_secret` is unset - (File: `lib/shipit/github_app.rb`, `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
The Deriverse bug is a "trust the input when the verification mechanism is not configured" pattern: with no oracle configured, the unsigned spot price is used directly for liquidation math. The same pattern exists in the Shipit `WebhooksController`: `GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for the organization, so the entire webhook payload — including `membership` events that mutate `Team`/`Membership` records used for `Shipit.github_teams` authorization — is trusted without any cryptographic check.

### Finding Description
`GitHubApp#verify_webhook_signature` is the single gate protecting `/webhooks`: [1](#0-0) 

If the operator does not set `webhook_secret` for an organization (shown as the documented/example default, e.g. blank in `config/secrets.development.example.yml`, `template.rb`, and described as "(optional)" in `docs/setup.md`), `verify_webhook_signature` returns `true` for *any* payload, regardless of the `X-Hub-Signature` header.

`WebhooksController#verify_signature` looks up the `GitHubApp` purely from attacker-controlled JSON in the (unverified) payload: [2](#0-1) 

Once the payload passes this no-op check, `Shipit::Webhooks.for_event('membership')` dispatches to `MembershipHandler`, which trusts the `team` and `member` sub-objects of the JSON body directly: [3](#0-2) 

`find_or_create_team!` finds-or-creates a `Team` keyed only by the attacker-supplied `team.id` (GitHub team ID), and `team.add_member(member)` appends an attacker-chosen login to that team's membership: [4](#0-3) 

`User.find_or_create_by_login!` will create/fetch a `User` record for any login the attacker names (it only hits the GitHub API to enrich profile metadata, it does not verify the claimed webhook event actually happened on GitHub): [5](#0-4) 

Team membership is exactly the authorization boundary used to gate access to the whole application: `User#authorized?` checks membership in `Shipit.github_teams`: [6](#0-5) 
and `Authentication#force_github_authentication` denies access to any user that is not `authorized?`: [7](#0-6) 

The broken binding, stated as an equality that should hold but doesn't:
`organization whose GitHub App cryptographically signed this membership event == organization whose Team/Membership records are mutated to satisfy Shipit.github_teams`.
When `webhook_secret` is absent, the left side collapses to "nobody" (no verification occurs at all), while the right side is still fully honored — an unauthenticated POST can freely rewrite the source of truth for privileged-team membership.

### Impact Explanation
This maps to the explicitly in-scope High-severity category: "escalation into `Shipit.github_teams` authorization." An attacker who already has (or creates via OAuth) an ordinary, unprivileged Shipit account can forge a `membership` `action: added` event naming their own GitHub login and the `github_id` of a privileged team, and the Shipit instance will add them to that team, granting full application access that `force_github_authentication` otherwise blocks. This is a genuine confused-deputy vulnerability rooted in the engine's own webhook trust model, not merely a downstream effect of the host skipping documented mounting steps — `webhook_secret` is explicitly modeled and shipped as optional/blank in the engine's own templates and setup docs.

### Likelihood Explanation
Exploitability depends entirely on whether the deployment has configured `webhook_secret` for the relevant GitHub organization. Because the engine's own templates (`template.rb`), example secrets (`config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`) and setup docs present `webhook_secret` as optional and blank by default, and because `verify_webhook_signature`'s fail-open behavior (`return true unless webhook_secret`) makes an unset secret a "silently disabled security control" rather than a hard requirement, this is a plausible and realistic misconfiguration for an engine that markets itself as easy to stand up. I could not verify from the index whether `webhook_secret` is enforced as mandatory anywhere else (e.g., in an initializer or a startup check) — this is an area worth confirming with the full repository if further certainty is needed.

### Recommendation
Make `webhook_secret` mandatory (fail closed, not open) for any organization that has `membership`/other privilege-affecting webhooks enabled, or refuse to process `membership` events at all unless the signature was cryptographically verified. Consider deriving `Team`/`Membership` state from GitHub's REST API rather than trusting webhook payload contents directly, mirroring the `TWAP`/external-oracle recommendation in the original report: use an authoritative side channel instead of a bare, optionally-unauthenticated push notification for security-critical state.

### Proof of Concept
1. Deploy Shipit with an organization entry in `secrets.yml` whose `webhook_secret` is left blank (the documented default/optional state).
2. As an unprivileged attacker with any GitHub login (no Shipit session, no GH App credentials, no repo access needed), send:
```
POST /webhooks
X-Github-Event: membership
Content-Type: application/json

{
  "action": "added",
  "team": { "id": <github_id of Shipit.github_teams entry>, "name": "Privileged", "slug": "privileged", "url": "https://example.com" },
  "organization": { "login": "<configured-org>" },
  "member": { "login": "<attacker-github-login>" }
}
```
3. Because `webhook_secret` is unset, `verify_webhook_signature` returns `true` unconditionally [1](#0-0) , `MembershipHandler#process` runs and calls `team.add_member(member)` [4](#0-3) , creating a `Membership` row for the attacker's `User` in the privileged `Team`.
4. The attacker logs into Shipit via OAuth using that same GitHub login; `User#authorized?` now returns `true` [6](#0-5) , bypassing the `Shipit.github_teams` restriction enforced in `Authentication#force_github_authentication` [7](#0-6) .

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-44)
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
