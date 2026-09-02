### Title
Fail-open webhook signature verification lets an unauthenticated attacker forge `membership` events and self-grant `Shipit.github_teams` authorization - ([File: lib/shipit/github_app.rb])

### Summary
`GithubApp#verify_webhook_signature` treats a blank `webhook_secret` as an automatic "verified" result instead of rejecting the request, exactly mirroring the external report's bug class: a security-critical parameter (`_owner` / here `webhook_secret`) is allowed to be empty/unset, and the code takes the unsafe branch instead of failing closed. Because `webhook_secret` is documented as *optional* per organization, any Shipit deployment (or any single organization in a multi-org deployment) that omits it will accept **any** unsigned, attacker-crafted webhook body as authentic, letting an outside attacker drive privileged application state — most severely, self-granting membership in a `Shipit.github_teams`-authorized team.

### Finding Description
`WebhooksController` gates all incoming webhooks behind `verify_signature`, which is expected to authenticate the payload: [1](#0-0) 

The actual check delegates to `GithubApp#verify_webhook_signature`, which fails open when no secret is configured for the resolved organization: [2](#0-1) 

`webhook_secret` is explicitly documented as optional (`Webhook secret (optional): Fill it with some randomly generated string...`), and every shipped example config (`config/secrets.development.example.yml`, `test/dummy/config/secrets_double_github_app.yml`, `template.rb`) ships it as `nil`/blank by default, so this is a realistically-reached, in-scope configuration state rather than a deviation from documented mounting. [3](#0-2) [4](#0-3) 

Once the signature check is bypassed, `Shipit::Webhooks::Handlers::MembershipHandler` trusts the entire payload — `team`, `organization.login`, and `member.login` — none of which are otherwise re-validated against a real GitHub state, to find-or-create a `Team` and add the named member to it: [5](#0-4) 

`Team#add_member` performs no additional check that the member is actually a GitHub member of that team: [6](#0-5) 

Finally, `User#authorized?` — the exact gate used by `force_github_authentication` to allow any logged-in GitHub user into the whole application — is computed purely from local `teams` membership rows: [7](#0-6) [8](#0-7) 

**The broken binding**: "the organization whose webhook the app claims to have cryptographically authenticated" must equal "the organization/team membership records the handler is permitted to mutate." When `webhook_secret` is blank, `verify_webhook_signature` always returns `true`, so this equality never actually holds — an attacker who has never proven any relationship to the target GitHub organization can still write directly into the `Team`/`Membership` tables that gate `Shipit.github_teams` authorization.

### Impact Explanation
This directly reaches the "High - escalation into `Shipit.github_teams` authorization" impact category. An attacker who:
1. Logs in to Shipit through the normal GitHub OAuth flow with any GitHub account (no special privilege needed) — this only requires being a legitimate GitHub user, obtaining a `User` record with their real `github_id`/`login`.
2. POSTs a forged `membership` webhook (`action: 'added'`, `team` matching an org configured in `Shipit.github_teams`, `member.login` = their own login) to `/webhooks` with any (or no) `X-Hub-Signature` header, targeting an organization whose configuration in Shipit has no `webhook_secret` set,

will have their own `User` inserted into a `Team` that back the `authorized?` check, bypassing the intended requirement of actually belonging to the configured GitHub team/organization, and gain full authenticated access to the Shipit UI/API (deploy triggers, rollbacks, stack management) as an "authorized" user.

### Likelihood Explanation
Moderate-to-high: it requires only (a) an organization configured without a `webhook_secret`, which the project's own documentation and every shipped example config treat as the normal/default case, and (b) knowledge of the numeric `team.id`/`slug`/`organization.login` of a real team referenced by `Shipit.github_teams` (obtainable from public GitHub org/team pages). No GitHub App credentials, `ApiClient` token, or `webhook_secret` knowledge is required — the entire premise is that no secret exists to know.

### Recommendation
Change `verify_webhook_signature` to fail closed: reject (return `false`/422) when `webhook_secret` is not configured, or make `webhook_secret` mandatory for any organization that registers webhook-driven handlers (especially `membership`), rather than silently trusting unsigned payloads. Additionally, `MembershipHandler`/`Team#add_member` should not be reachable at all for organizations without a verified webhook channel, and ideally should reconcile against `Shipit.github.api` team membership rather than trusting the payload outright.

### Proof of Concept
1. Deploy Shipit with an organization entry in `github:` that omits `webhook_secret` (the documented default/optional state).
2. As any external attacker with a valid GitHub account, log in via `/github/auth/github` (normal OAuth), creating a `User` row with your real `login`/`github_id`.
3. Send an unsigned (or arbitrarily-signed) POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": <real-team-id>, "name": "<team>", "slug": "<slug>", "url": "https://api.github.com/teams/<id>" },
  "organization": { "login": "<org-in-Shipit.github_teams>" },
  "member": { "login": "<your-github-login>" }
}
```
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "<org>").verify_webhook_signature(...)`, which returns `true` unconditionally because `webhook_secret` is blank for that org.
5. `MembershipHandler#process` finds/creates the `Team` and calls `team.add_member(User.find_or_create_by_login!("<your-github-login>"))`, adding you to the team.
6. Log back into Shipit; `current_user.authorized?` now returns `true` via `teams.where(id: Shipit.github_teams.map(&:id)).exists?`, granting full application access despite never having been a real member of that GitHub team/organization.

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

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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
