## Analog Vulnerability Found

### Title
Webhook Signature Verification Silently No-ops For Any Configured GitHub Organization Missing A `webhook_secret`, Allowing Forged `membership` Events To Escalate Into `Shipit.github_teams` Authorization - (File: `lib/shipit/github_app.rb`)

### Summary
The external report's root cause is a binding break between the value an authorization decision is based on (spot price at claim time) and the value that should have been verified/committed to (average price over the staking period). The analogous binding in Shipit is: the **organization that the webhook signature is authenticated against** (derived from an attacker-controlled field in the unauthenticated JSON body) versus **the organization for which a `webhook_secret` is actually configured**. When the two diverge — i.e., the attacker names an organization that is configured in `Shipit.github` but has no `webhook_secret` set — signature verification is skipped entirely, and the forged payload is processed as if it came from GitHub.

### Finding Description
`Shipit::WebhooksController#verify_signature` selects a `GitHubApp` instance keyed off of an attacker-controlled field in the raw, not-yet-verified POST body: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')` — both are plain JSON fields inside the unauthenticated body, fully attacker-controlled at this point (`verify_signature` runs *before* signature validity is known).

That value picks the `GitHubApp` used to verify the HMAC: [3](#0-2) 

Critically, `verify_webhook_signature` **returns `true` unconditionally when `webhook_secret` is blank** for the selected organization (`return true unless webhook_secret`). Multiple organizations can be configured in a single Shipit deployment (`Shipit.github(organization:)`, tested via `test/dummy/config/secrets_double_github_app.yml`), and nothing in the setup docs or code enforces that every configured organization has a `webhook_secret` set — the shipped templates default it to blank/nil: [4](#0-3) [5](#0-4) 

So the equality this binding is supposed to preserve is: `organization authenticated (HMAC verified against secret S) == organization whose repository/team state is mutated by the handler`. It breaks whenever an operator has configured a second organization (e.g., for a lower-trust or staging org) without a webhook secret: an unprivileged external attacker who knows nothing about any secret can set `organization.login` (or `repository.owner.login`) to that unsecured org's name, and `verify_signature` will accept the request with **no signature at all**, because `X-Hub-Signature` is never even parsed/compared for that branch.

The forged payload is then dispatched to real handlers, e.g. `Shipit::Webhooks::Handlers::MembershipHandler`, which trusts `params.team` / `params.organization` / `params.member` wholesale to create teams and add/remove members: [6](#0-5) 

If the forged `team.id`/`slug` happens to correspond to (or is later configured as) one of `Shipit.github_teams` (built from `github.oauth.teams`), an attacker-added `member.login` gains passage through the authorization check used on every controller: [7](#0-6) [8](#0-7) [9](#0-8) 

### Impact Explanation
This is an escalation into `Shipit.github_teams` authorization: an attacker with no Shipit session, no `ApiClient` token, and no knowledge of any `webhook_secret` can forge a `membership` webhook event, add an arbitrary GitHub login to a `Team` record tracked by Shipit, and thereby satisfy `User#authorized?` the next time that GitHub user completes OAuth login — bypassing the team-membership gate that `force_github_authentication` otherwise enforces on every page/action in the engine. This matches the explicitly allowed High-severity impact category ("escalation into `Shipit.github_teams` authorization").

### Likelihood Explanation
Requires: (1) the deployment configures more than one GitHub organization via `Shipit.github`/`TOP_LEVEL_GH_KEYS`, and (2) at least one of those organizations is left without a `webhook_secret` (the shipped default templates literally comment it as blank). This is a realistic multi-tenant/staging configuration mistake rather than a hypothetical one, and the code path requires zero credentials to exploit once that condition holds — only knowledge of the org's login name and the `/webhooks` endpoint, both public.

### Recommendation
- Require `webhook_secret` to be present for every configured organization at boot (fail closed), or globally reject webhooks (422) for any organization resolved to a `GitHubApp` with no `webhook_secret`, instead of treating a missing secret as automatically verified.
- Do not let attacker-supplied JSON body fields select the trust anchor used to verify that very same body; consider deriving the organization from a static per-install fallback secret independent of the body content when only a single organization/secret model is intended.

### Proof of Concept
1. Deploy configures two organizations in `Shipit.github`, e.g. `trusted-org` (with `webhook_secret` set) and `staging-org` (left blank, matching the shipped template default).
2. Attacker sends, with no `X-Hub-Signature` header (or any garbage value):
```
POST /webhooks
X-Github-Event: membership

{
  "action": "added",
  "team": { "id": 999, "name": "Shipit", "slug": "shipit", "url": "https://example.com" },
  "organization": { "login": "staging-org" },
  "member": { "login": "attacker-github-login" }
}
```
3. `repository_owner` resolves to `staging-org`; `Shipit.github(organization: 'staging-org').verify_webhook_signature(...)` hits `return true unless webhook_secret` and returns `true` unconditionally, since `staging-org` has no secret configured — per `lib/shipit/github_app.rb:76-83`.
4. `MembershipHandler#process` runs unauthenticated, creating/attaching `attacker-github-login` to team id `999`.
5. If team `999`/slug `shipit` is (or later becomes) part of `Shipit.github_teams` (`github.oauth.teams`), the attacker's GitHub account passes `User#authorized?` on next OAuth login, bypassing the team-restriction gate enforced by `Shipit::Authentication#force_github_authentication`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L6-18)
```yaml
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
```

**File:** template.rb (L66-111)
```ruby
      host: 'http://localhost:3000'
      redis_url: redis://localhost
      github:
        domain: # defaults to github.com
        bot_login:
        app_id:
        installation_id:
        webhook_secret:
        private_key:
        oauth:
          id:
          secret:
          # team: MyOrg/developers # Enable this setting to restrict access to only the member of a team

    test:
      app_name: My Shipit
      secret_key_base: #{SecureRandom.hex(64)}
      host: 'http://localhost:4000'
      redis_url: redis://localhost
      github:
        domain: # defaults to github.com
        bot_login:
        app_id:
        installation_id:
        webhook_secret:
        private_key:
        oauth:
          id: <%= ENV['GITHUB_OAUTH_ID'] %>
          secret: <%= ENV['GITHUB_OAUTH_SECRET'] %>
          # teams: MyOrg/developers # Enable this setting to restrict access to only the member of a team

    production:
      app_name: My Shipit
      secret_key_base: <%= ENV['SECRET_KEY_BASE'] %>
      host: <%= ENV['SHIPIT_HOST'] %>
      redis_url: <%= ENV['REDIS_URL'] %>
      github:
        domain: # defaults to github.com
        app_id: <%= ENV['GITHUB_APP_ID'] %>
        installation_id: <%= ENV['GITHUB_INSTALLATION_ID'] %>
        webhook_secret:
        private_key:
        oauth:
          id: <%= ENV['GITHUB_OAUTH_ID'] %>
          secret: <%= ENV['GITHUB_OAUTH_SECRET'] %>
          # teams: MyOrg/developers # Enable this setting to restrict access to only the member of a team
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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
