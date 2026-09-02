### Title
Webhook signature verification is silently bypassed for any GitHub organization configured without a `webhook_secret`, allowing unauthenticated forgery of `membership` events that grant `Shipit.github_teams` authorization - (File: `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` picks a per-organization `GithubApp` config from the *unauthenticated* JSON body and delegates signature checking to `GithubApp#verify_webhook_signature`. That method returns `true` whenever the configured `webhook_secret` is blank (`return true unless webhook_secret`) — i.e., no verification occurs at all. Because `config/secrets*.yml` and `docs/setup.md` explicitly document `webhook_secret` as *optional*, an org can legitimately run with `webhook_secret: nil`. For such an org, anyone on the internet can POST an arbitrary, unsigned payload to `/webhooks` and have it processed as if it originated from GitHub, breaking the binding: "organization that authenticated the webhook" == "the Shipit records the webhook is allowed to mutate."

### Finding Description
`WebhooksController#verify_signature` derives the org from attacker-controlled JSON before any cryptographic check: [1](#0-0) [2](#0-1) 

The signature check itself no-ops when the org's secret is unset: [3](#0-2) 

With `webhook_secret` blank for the targeted organization, `verified` is always `true`, so `create` dispatches the attacker's raw JSON straight to the registered handlers: [4](#0-3) 

The most impactful handler is `MembershipHandler`, which creates/loads a `Team` and a `User` purely from payload fields and mutates team membership with no further authorization check: [5](#0-4) 

`Team` membership is exactly what gates access to the whole application: `User#authorized?` checks membership in `Shipit.github_teams`, and `Authentication#force_github_authentication` renders the app forbidden unless `authorized?` is true: [6](#0-5) [7](#0-6) 

So an attacker who merely knows (or guesses) the name of an org configured in this Shipit instance without a `webhook_secret` can forge a `membership`/`added` event naming their own GitHub login and one of the `Shipit.github_teams`, causing Shipit to create a `Membership` row for them. When they subsequently complete real GitHub OAuth (`GithubAuthenticationController#callback` → `User.find_or_create_from_github`), `authorized?` now returns `true` for them even though GitHub itself never added them to that team. [8](#0-7) 

This is the same bug class as the reported `registerTradeAndBorrow` issue: a value/authorization is credited (`team.add_member`) based on a "trusted" event whose trust was never actually established, letting the attacker "double-dip" into a privilege they never earned via the legitimate GitHub-side channel.

### Impact Explanation
This is an unauthenticated escalation directly into `Shipit.github_teams` authorization (explicitly listed High-impact category), the gate that controls access to viewing/triggering deploys and stack state across every repository configured on the instance. No Shipit session, API token, or GitHub credential is required — only knowledge of an org name configured with a blank `webhook_secret` and a real GitHub account to later authenticate with.

### Likelihood Explanation
`webhook_secret` is explicitly documented as optional (`docs/setup.md`, `config/secrets.development.shopify.yml` template), so operators following the documented setup can end up in this state without doing anything "wrong" by the engine's own instructions. The `verify_webhook_signature` early-return on blank secret is unconditional engine code, not a host-app misconfiguration outside the documented setup.

### Recommendation
- Make `verify_webhook_signature` fail closed (return `false`) when `webhook_secret` is blank, or require `webhook_secret` to be present at boot for any configured organization that has webhook-driven handlers enabled (e.g., `membership`).
- Alternatively, disable dispatching of privilege-affecting events (`membership`) entirely when signature verification is not cryptographically enforced for that organization.

### Proof of Concept
1. Configure (or identify) an organization in `Shipit.github` config with `webhook_secret` left blank, as permitted by `docs/setup.md`.
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: membership` and no valid `X-Hub-Signature`, body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Privileged", "slug": "privileged", "url": "https://example.com" },
  "organization": { "login": "<the-org-with-blank-secret>" },
  "member": { "login": "attacker-github-login" }
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "<org>").verify_webhook_signature(...)`, which returns `true` unconditionally because `webhook_secret` is blank.
4. `MembershipHandler#process` creates/finds `Team` (organization = attacker-chosen) and adds `attacker-github-login` as a member.
5. Attacker logs in normally via GitHub OAuth; `User#authorized?` now returns `true` if the forged team matches one in `Shipit.github_teams`, granting full application access without ever being a real member of that GitHub team.

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

**File:** app/controllers/shipit/github_authentication_controller.rb (L30-34)
```ruby
    def sign_in_github(auth)
      user = User.find_or_create_from_github(auth.extra.raw_info)
      user.update(github_access_token: auth.credentials.token)
      user.id
    end
```
