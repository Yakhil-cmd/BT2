### Title
Optional `webhook_secret` reduces `verify_webhook_signature` to a no-op, letting an unauthenticated attacker forge GitHub webhooks and escalate into `Shipit.github_teams` authorization - ([File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` is supposed to bind every event it processes to an authentic GitHub sender via HMAC verification of `X-Hub-Signature`. But `GitHubApp#verify_webhook_signature` unconditionally returns `true` whenever no `webhook_secret` is configured for the organization derived from the payload, and the setup documentation explicitly presents `webhook_secret` as *optional*. In that (documented) configuration, the "authenticated GitHub organization" side of the binding is never actually checked against anything — any unprivileged network attacker can submit a `membership` event and have `MembershipHandler` add an arbitrary GitHub login to a `Shipit::Team`, which is exactly the set backing `User#authorized?` / `Shipit.github_teams`.

### Finding Description
The equality that should hold is:

`organization whose secret cryptographically signed the request == organization whose webhook events are trusted and acted upon`

`WebhooksController#verify_signature` computes `repository_owner` straight from the untrusted JSON body and looks up that org's `GitHubApp`: [1](#0-0) 

It then delegates trust entirely to `verify_webhook_signature`: [2](#0-1) 

`return true unless webhook_secret` means that whenever `@config[:webhook_secret]` is blank for that organization, **every** payload is treated as verified, regardless of the (attacker-controlled or absent) `X-Hub-Signature` header. `webhook_secret` is initialized straight from user-supplied engine config with no fallback/enforcement: [3](#0-2) 

Crucially, this is not a misconfiguration outside the documented deployment model — the official setup guide tells operators the webhook secret is optional: [4](#0-3) 
and the generated secrets templates ship with `webhook_secret:` empty by default: [5](#0-4) 

Once the signature check is neutralized, the controller dispatches the raw, attacker-supplied JSON straight to handlers with no other authentication layer: [6](#0-5) 

For the `membership` event, `MembershipHandler` blindly creates/uses a team and adds the attacker-chosen `member.login` as a member, with no cross-check against real GitHub state: [7](#0-6) 

That team membership is exactly what gates application-wide access: `User#authorized?` is computed as membership in `Shipit.github_teams`: [8](#0-7) 
and `Authentication#force_github_authentication` uses `current_user.authorized?` to gate every controller in the engine: [9](#0-8) 

### Impact Explanation
Before the attack: only real GitHub `membership` webhooks (or a session already belonging to a team member) can grant `Shipit.github_teams` membership. After a single forged `membership` webhook, an unauthenticated network attacker can insert an arbitrary GitHub login into an authorized team's roster. If that GitHub login is one the attacker controls (or is later linked through OAuth by `find_or_create_by_login!`/`create_from_github`), the attacker becomes `authorized?` and gains full access to the Shipit UI/API for that installation — stacks, deploy triggers, rollbacks, etc. This is a direct instance of the listed High-impact category: "escalation into `Shipit.github_teams` authorization," achieved with no credential, no repository write access, and no privileged account, only reachability of `/webhooks` and knowledge of an organization name/team id already configured in Shipit — both of which are public/discoverable.

### Likelihood Explanation
`webhook_secret` being optional is an explicitly documented supported configuration, not a hardening failure the host app must avoid; any Shipit deployment following the official setup doc without filling in the optional secret is affected. No signature guessing, brute forcing, or side channel is required — the check is a pure `true` short-circuit. The only precondition is that the target organization's `webhook_secret` is unset, which is the default value shown in the shipped secrets templates.

### Recommendation
- Do not treat `webhook_secret` as optional at the code level: require a non-blank secret to be configured before accepting any webhook for that organization, and reject (422) requests when it is missing rather than trivially accepting them.
- Update `docs/setup.md` and the secrets templates to mark `webhook_secret` as mandatory, or fail fast at boot (`Shipit.github_app_config`) when it is absent.
- Add a regression test asserting that `verify_webhook_signature` returns `false` (not `true`) when `webhook_secret` is blank.

### Proof of Concept
1. Deploy Shipit using the documented, "optional" webhook secret setup (leave `github.<org>.webhook_secret` blank, as in `config/secrets.development.shopify.yml`).
2. As an unauthenticated network attacker, POST to `/webhooks` with headers `X-Github-Event: membership` and no valid `X-Hub-Signature`, and a body:
```json
{
  "action": "added",
  "team": {"id": 48, "name": "Developers", "slug": "developers", "url": "https://example.com"},
  "organization": {"login": "<configured-org>"},
  "member": {"login": "attacker-controlled-login"},
  "repository": {"owner": {"login": "<configured-org>"}}
}
```
3. `verify_signature` calls `GitHubApp#verify_webhook_signature`, which returns `true` because `webhook_secret` is blank, so the request passes.
4. `MembershipHandler#process` adds `attacker-controlled-login` to the `Developers` team.
5. If `Developers` is part of `Shipit.github_teams`, any user later resolved to that GitHub login becomes `authorized?` and gains full access to the Shipit engine.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** config/secrets.development.shopify.yml (L5-10)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
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
