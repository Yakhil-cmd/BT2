### Title
Unsigned webhook payload trusted for team membership grants when `webhook_secret` is absent - escalation into `Shipit.github_teams` authorization ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` treats a blank/unconfigured `webhook_secret` as automatic verification success, which is the exact same bug class as the report: a security check is gated on a value that defaults to "unset," and when unset the check becomes a tautology (`return true unless webhook_secret` ≈ `100*holdings >= 0*loan`). Combined with `MembershipHandler`, this lets an unauthenticated caller directly grant themselves membership in a `Team` that gates `User#authorized?`, breaking the binding "payload accepted as authentic GitHub webhook" ⇔ "payload actually originated from GitHub, verified via HMAC of `webhook_secret`."

### Finding Description
`WebhooksController#verify_signature` resolves the `GitHubApp` for the organization named in the payload and calls `verify_webhook_signature`: [1](#0-0) 

The actual check is: [2](#0-1) 

`@webhook_secret` is set from `@config[:webhook_secret].presence`, i.e. `nil` when unset: [3](#0-2) 

If `webhook_secret` is blank for the organization being addressed, `verify_webhook_signature` unconditionally returns `true`, regardless of the actual `X-Hub-Signature` header or payload contents — identical in structure to `liquidationThresholdPercent = 0` making `belowMaintenanceThreshold` always true. Once "verified," `WebhooksController#create` dispatches the raw attacker-controlled JSON straight into the `membership` handler: [4](#0-3) [5](#0-4) 

`MembershipHandler#process` trusts `params.member.login` and `params.action == 'added'` to call `team.add_member(member)` with no further validation against GitHub: [5](#0-4) 

Team membership is exactly what gates authorization in this engine: [6](#0-5) 

The repository's own documentation and generator template treat a blank `webhook_secret` as a normal, expected configuration state, not an edge case: [7](#0-6) [8](#0-7) 

### Impact Explanation
If any configured GitHub organization/app has no `webhook_secret` set (a state the shipped templates and dev-secrets examples explicitly produce), an unauthenticated network attacker can POST a forged `membership` webhook naming any GitHub login as `member` and any team the attacker wants (or a team already tied to `Shipit.github_teams`) with `action: added`. This directly grants that login membership in the authorizing `Team` record and bypasses the actual GitHub team check that `User#authorized?` is supposed to enforce — an escalation into `Shipit.github_teams` authorization, per the listed High-impact category. The same bypass also allows spoofing `push`, `status`, `check_suite`, etc., letting an attacker inject fabricated commit statuses or trigger sync jobs for any tracked repository/organization lacking a secret.

### Likelihood Explanation
This requires no credentials, no `ApiClient` token, and no GitHub session — only knowledge (or a guess) that a given organization's `webhook_secret` is unset, which is a state the project's own setup docs and generator templates present as acceptable/default (`webhook_secret: # nil`). Any deployment that follows the documented dev/example config, or that simply never got around to filling in `webhook_secret` for a secondary organization in a multi-org setup, is immediately exposed. The endpoint (`/github/webhooks` route, mounted per `config/routes.rb`) is public by design (webhooks must be reachable by GitHub), so no additional access is needed to reach the vulnerable code path.

### Recommendation
Do not treat an absent `webhook_secret` as "verification passes." Instead:
- Require `webhook_secret` to be present for every configured GitHub organization at boot/config-load time (fail fast, similar to requiring a non-zero default `liquidationThresholdPercent` in `CrossMarginTrading`), or
- If a secretless/dev-only mode must be supported, gate it behind an explicit, separate development-only flag (e.g. `Shipit.disable_webhook_signature_verification`) rather than an implicit `nil` fallback in `verify_webhook_signature`, and never allow this flag to be reachable in production configuration templates/examples.

### Proof of Concept
1. Configure (or use the shipped example configuration) a GitHub organization `attacker-org` (or any org already used by a tracked stack) with `webhook_secret` left blank, as shown in `config/secrets.development.example.yml`.
2. Send, with no authentication and no valid `X-Hub-Signature`:
```
POST /github/webhooks
X-Github-Event: membership

{
  "action": "added",
  "team": {"id": 999, "name": "Deployers", "slug": "deployers", "url": "https://api.github.com/teams/999"},
  "organization": {"login": "attacker-org"},
  "member": {"login": "attacker-controlled-login"}
}
```
3. `verify_signature` calls `Shipit.github(organization: "attacker-org").verify_webhook_signature(...)`, which returns `true` because `webhook_secret` is blank (`lib/shipit/github_app.rb:76-83`).
4. `MembershipHandler#process` creates/finds `Team` #999 and adds `attacker-controlled-login` as a member (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`), with no real GitHub verification that this membership exists.
5. If `Team` #999 is (or is later configured as) one of `Shipit.github_teams`, the corresponding `User` record now satisfies `User#authorized?` (`app/models/shipit/user.rb:80-82`) without ever having been authorized by GitHub.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** config/secrets.development.example.yml (L1-17)
```yaml
host: 'localhost:3000'
redis_url: 'redis://127.0.0.1:6379/0'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app
# Can be obtained there: https://github.com/settings/apps
# Set the "Authorization callback URL" as `<host>/github/auth/github/callback`

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

**File:** template.rb (L97-112)
```ruby
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
      env:
```
