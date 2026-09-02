### Title
Unauthenticated webhook forgery when `webhook_secret` is unset leads to escalation into `Shipit.github_teams` authorization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::GitHubApp#verify_webhook_signature` treats a blank/unset `webhook_secret` as an automatic "verified" result instead of rejecting the request, exactly analogous to the reported bug class of trusting a value that can legitimately be zero/absent. Because the webhook secret is documented as *optional*, any Shipit deployment that leaves it unset accepts **unsigned, attacker-forged GitHub webhooks**, including `membership` events that write `Shipit::Membership` rows binding an arbitrary GitHub login to a `Shipit::Team`. If that team is one of `Shipit.github_teams`, the attacker's own account becomes "authorized" application-wide after a normal OAuth login.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App config for the organization named in the *unverified* payload and asks it to verify the signature: [1](#0-0) 

The verification itself is a no-op when no secret is configured: [2](#0-1) 

`@webhook_secret` is only set from config and is optional per the setup documentation and default secrets templates: [3](#0-2) 

So the equality the engine implicitly relies on is:
`verified == (signature cryptographically matches payload)`

but the actual code enforces:
`verified == (webhook_secret configured) ? (signature matches) : true`

When `webhook_secret` is blank for an organization (an explicitly supported, "optional" configuration), the right-hand side collapses to `true` unconditionally — breaking the binding between "GitHub authenticated this payload" and "Shipit accepted this payload."

Once accepted, the `membership` event handler writes team membership directly from payload fields with no further authentication: [4](#0-3) 

Team membership is precisely what gates application-wide authorization: [5](#0-4) [6](#0-5) 

### Impact Explanation
This crosses the boundary explicitly called out as High impact: "escalation into `Shipit.github_teams` authorization." An attacker with no Shipit session, no `ApiClient` token, and no knowledge of any secret can post a forged `membership` webhook naming an organization whose `webhook_secret` is blank, adding themselves (via `member.login`) to a `Team` that belongs to `Shipit.github_teams`. After a routine GitHub OAuth login (`GithubAuthenticationController#callback` / `User.find_or_create_from_github`), `current_user.authorized?` returns `true`, granting full access to stacks, deploys, rollbacks, and locks that would otherwise require org-team membership.

### Likelihood Explanation
The webhook secret is explicitly documented as optional ("Webhook secret (optional): ..."), and the shipped default configuration templates leave it `nil`. Any operator who follows the minimal setup path, or who runs a multi-organization configuration where one org's secret was never filled in, is exposed. No credentials, GitHub App private key, or prior access are required — only knowledge of the target organization's login and a `Team`'s numeric `github_id` (which is discoverable/observable via normal GitHub team URLs) that is registered in `Shipit.github_teams`.

### Recommendation
Fail closed instead of open when no secret is configured: reject webhook signature verification (or refuse to boot/serve the webhooks endpoint) unless a `webhook_secret` is present for every configured organization, mirroring the recommended fix pattern from the report (require a value rather than silently accepting the "empty" case). Concretely, change:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```
to reject (`return false`) when `webhook_secret` is blank, and make `webhook_secret` a mandatory configuration key with a hard startup validation error if missing.

### Proof of Concept
1. Configure (or discover) a Shipit organization block that has `webhook_secret` left blank, as shown in the shipped example config: [7](#0-6) .
2. Attacker (no session, no token) sends:
```
POST /webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=anything-or-empty
Content-Type: application/json

{
  "action": "added",
  "organization": { "login": "<target-org-with-blank-secret>" },
  "team": { "id": <github_id of a Team already tracked and listed in Shipit.github_teams>, "name": "Devs", "slug": "devs", "url": "https://example.com" },
  "member": { "login": "<attacker-github-login>" }
}
```
3. `verify_signature` calls `Shipit.github(organization: "<target-org>")`, whose `verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is blank — see [2](#0-1) .
4. `Handlers::MembershipHandler#process` runs `team.add_member(member)`, creating a `Shipit::Membership` for `<attacker-github-login>` — see [4](#0-3) .
5. Attacker logs in via `/github/auth/github` with their real GitHub account; `current_user.authorized?` now returns `true` because their `User` is a member of a team in `Shipit.github_teams` — see [5](#0-4) , granting full access normally reserved for the org's approved teams.

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

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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
