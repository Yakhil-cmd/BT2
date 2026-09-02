### Title
Blank `webhook_secret` Makes `verify_webhook_signature` Trivially Pass, Allowing Unauthenticated Forged Webhooks and `Shipit.github_teams` Authorization Escalation - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the configured `webhook_secret` is blank, exactly mirroring the reported bug class: a "zero"/empty credential causes signature verification to trivially succeed instead of failing closed. Because the engine's docs and example configs explicitly allow `webhook_secret` to be left empty, and nothing enforces it must be non-blank, an unprivileged attacker who knows (or guesses) a target's setup can send unsigned/arbitrarily-signed webhook requests that are accepted as authentic, and use the `membership` event to add themselves to a `Team` that backs `Shipit.github_teams`, escalating into full application authorization.

### Finding Description
`GitHubApp#initialize` sets `@webhook_secret = @config[:webhook_secret].presence`, so a missing or blank secret becomes `nil`. [1](#0-0) 

`verify_webhook_signature` then does:
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

This is the direct analog of the `rfqOrderSigner == address(0)` bug: instead of the verification logic being disabled by a zero-address comparison, it is disabled by a nil/blank secret comparison — `unless webhook_secret` trivially returns `true` for *any* signature (even a garbage or missing one), bypassing HMAC verification entirely. Both the setup docs and the shipped example config explicitly present `webhook_secret` as optional / commented out with no enforcement that it must be set: [3](#0-2) [4](#0-3) 

`WebhooksController#verify_signature` relies entirely on this method to gate all inbound events: [5](#0-4) 

The binding broken is: **(authenticated GitHub sender per `webhook_secret`) == (any HTTP requester)** whenever `webhook_secret` is unset — before the attacker's request, only GitHub (holder of the shared secret) could deliver events; after, an unauthenticated actor can deliver arbitrary events.

The highest-value exploitation path is the `membership` webhook, handled by `MembershipHandler`, which creates/looks up a `Team` by the attacker-supplied `team.id` and adds an attacker-chosen `member.login` (auto-vivified via `User.find_or_create_by_login!`) to that team: [6](#0-5) 

`Shipit.github_teams` is derived by resolving the configured OAuth team handles into `Team` records via `Team.find_or_create_by_handle`, which persists the real GitHub team `github_id`: [7](#0-6) [8](#0-7) 

`User#authorized?` grants access purely based on membership in a `Team` whose `id` is in `Shipit.github_teams`: [9](#0-8) 

Since a forged `membership` webhook with `action: 'added'`, the real (publicly discoverable) `team.id`/`slug`/`name` of the authorized org team, and an attacker's own GitHub `login` will match the existing `Team` record by `github_id` and add that user, this grants the attacker `authorized?` status without ever being a real member of the GitHub team.

### Impact Explanation
This escalates directly into `Shipit.github_teams` authorization bypass, one of the explicitly listed High-severity impacts: an attacker (with just their own GitHub login) can grant themselves membership in the team that gates access to Shipit, then log in via the normal GitHub OAuth flow and be treated as `authorized?`, gaining full application access (viewing/triggering deploys, rollbacks, stack management) that they were never entitled to.

### Likelihood Explanation
Likelihood is conditioned on the deployment leaving `webhook_secret` blank — which the engine's own documentation and shipped templates present as an acceptable, optional configuration (`docs/setup.md` line 30: "Webhook secret (optional)"). Any installation following the documented setup without explicitly filling in a webhook secret is exposed, and the webhook endpoint (`/webhooks`) is unauthenticated and internet-reachable by design, requiring no prior credentials, session, or repository access to exploit — only knowledge of the organization login and the target team's public GitHub `id`/`slug`.

### Recommendation
1. Fail closed instead of open: `verify_webhook_signature` should return `false` (not `true`) when `webhook_secret` is blank, or refuse to process webhooks at all for organizations without a configured secret.
2. Enforce at configuration load time that `webhook_secret` must be present for any organization entry in `Shipit.github`, raising a startup/config error otherwise (mirrors the report's recommendation to validate in the setter/initializer).
3. Defense-in-depth for `MembershipHandler`: do not trust webhook-delivered `member.login`/`team.id` for automatic authorization grants without an independent server-side re-verification (e.g., re-fetching the team membership from GitHub's API rather than trusting the payload).

### Proof of Concept
1. Target Shipit instance is configured per the documented "optional" webhook secret setup, i.e. `github.<org>.webhook_secret` is left blank as shown in the example configs.
2. Attacker (any external HTTP client, no credentials) sends:
```
POST /webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=deadbeef   # arbitrary/invalid

{
  "action": "added",
  "team": { "id": <real_github_team_id_of_authorized_team>, "name": "Developers", "slug": "developers", "url": "https://api.github.com/teams/x" },
  "organization": { "login": "<target-org>" },
  "member": { "login": "<attacker-github-login>" }
}
```
3. `WebhooksController#verify_signature` calls `verify_webhook_signature('sha1=deadbeef', raw_body)`, which returns `true` immediately because `webhook_secret` is `nil`, per `lib/shipit/github_app.rb` line 77.
4. `MembershipHandler#process` runs, finds the existing `Team` matching `github_id` (the real authorized team), fetches/creates a `User` for `attacker-github-login`, and calls `team.add_member(member)`.
5. Attacker logs into Shipit via the standard GitHub OAuth flow with `attacker-github-login`; `User#authorized?` now returns `true` because their `teams` include the `Team` whose `id` is in `Shipit.github_teams`, granting full unauthorized access to the application.

### Citations

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

**File:** config/secrets.development.shopify.yml (L1-19)
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
```

**File:** template.rb (L61-90)
```ruby
%w(config/secrets.yml config/secrets.example.yml).each do |path|
  create_file path, <<~CODE, force: true
    development:
      app_name: My Shipit
      secret_key_base: #{SecureRandom.hex(64)}
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

**File:** app/models/shipit/team.rb (L17-27)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end

      def fetch_and_create_from_github(organization, slug)
        return unless github_team = find_team_on_github(organization, slug)

        create!(github_team:, organization:)
      end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
