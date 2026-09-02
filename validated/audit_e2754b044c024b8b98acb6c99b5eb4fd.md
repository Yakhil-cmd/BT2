This confirms the exploit: `MembershipHandler.process` calls `team.add_member(member)` for any `params.team.id` / `params.member.login`, creating real `Membership` records that feed directly into `User#authorized?`'s `teams.where(id: Shipit.github_teams.map(&:id)).exists?` check [1](#0-0) . Since the org used for the signature check and the org whose event is actually processed can be decoupled (see below), an attacker can forge this event without any secret.

### Title
Gossipsub-style trust-binding break analog: webhook signature verified against attacker-chosen `repository.owner.login`, but event processed against a different `repository.full_name` — allows unauthenticated forgery of `membership`/`push`/`status` events, escalating into `Shipit.github_teams` authorization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, computed from `params.dig('repository','owner','login')` (or `organization.login`) [2](#0-1) . Every actual event `Handler` subclass, however, determines the target repository/org from a *different* field: `payload.dig('repository', 'full_name')` [3](#0-2) . Because both fields are independently attacker-controlled JSON in the raw POST body, and Shipit explicitly supports multiple GitHub organizations each with their own optional `webhook_secret` [4](#0-3) , an attacker can pick an org that has no `webhook_secret` configured (a supported, documented configuration — see `config/secrets.development.shopify.yml` lines 15-18 where `webhook_secret` is nil) to satisfy `repository.owner.login`, while setting `repository.full_name` (and `team`/`organization`/`member` fields for the `membership` event) to point at a fully protected org/repo. `verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank [5](#0-4) , so the whole payload is accepted with no valid signature at all, and then dispatched to handlers that act on the attacker-chosen target.

### Finding Description
The equality that should hold is: `organization whose secret authenticated the request == organization/repository the event handler acts on`. This binding is broken because:
- Signature verification org: `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [6](#0-5) .
- Event target org/repo: `Handler#repository_name = payload.dig('repository', 'full_name')`, resolved via `Repository.from_github_repo_name` [7](#0-6) , `app/models/shipit/repository.rb` lines 53-56.
- For `MembershipHandler`, the acted-upon organization/team is taken from independent, separately attacker-controlled fields `params.organization.login` and `params.team` [8](#0-7) , entirely unrelated to whatever `repository.owner.login` was used for the signature check.

Both `repository.owner.login`/`organization.login` (used for auth) and `repository.full_name`/`team`/`member` (used for effect) are fields inside the same attacker-supplied JSON body — there is no requirement that they refer to the same organization. An attacker who knows (or creates, if self-registration/any configured org with a blank secret exists) one organization slug with no `webhook_secret` set can use it purely to make `verify_webhook_signature` short-circuit to `true`, then supply arbitrary `team`, `organization.login`, and `member.login` values that reference the *real*, secret-protected organization's team, causing `MembershipHandler#process` to call `team.add_member(member)` — creating a real `Membership` row for an arbitrary GitHub login on a real authorization-gating `Team` [9](#0-8) .

`Shipit::User#authorized?` grants application access based purely on `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [1](#0-0) . If the attacker's own GitHub login (used to later complete real OAuth via `GithubAuthenticationController#callback` → `User.find_or_create_from_github`) matches the `member.login` forged into that team, the attacker becomes "authorized" in the target Shipit instance without ever being a real member of the required `Shipit.github_teams` — this is a direct authentication-boundary escalation. [10](#0-9) 

### Impact Explanation
This matches the explicitly listed High-severity bucket: "escalation into `Shipit.github_teams` authorization." An unprivileged, unauthenticated network attacker (no ApiClient token, no webhook secret, no repository write access, no GitHub App key) can grant themselves (or any chosen GitHub login) membership in a team that gates access to the whole Shipit instance, or alternatively forge `push`/`status`/`check_suite` events against protected repositories/stacks whose intended isolation is the per-organization `webhook_secret`.

### Likelihood Explanation
The `webhooks` endpoint requires no session, no API token — only knowledge of an organization slug configured in `Shipit.github` with a blank `webhook_secret`, which is an explicitly supported, documented configuration (`docs/setup.md` marks `webhook_secret` as something you "should copy... if you've set" one, implying it is optional) and is shown as `nil` for one of two orgs in the shipped sample config `config/secrets.development.shopify.yml`. Any multi-org Shipit deployment where at least one configured org omits `webhook_secret` is exploitable with a single crafted POST.

### Recommendation
Bind the organization used for signature verification to the same organization that handlers actually act on: derive `repository_owner` from the resolved `Repository`/`Team`/`Stack` record's own stored owner (looked up separately, not trusted verbatim from the JSON body), or require that `repository.owner.login`, `repository.full_name`'s owner segment, and (for `membership`) `organization.login` are all consistent and equal to the org whose secret was used, before dispatching to any handler. Additionally, consider requiring a non-blank `webhook_secret` for every configured organization (fail closed) rather than allowing per-org opt-out of signature verification.

### Proof of Concept
1. Configure Shipit with two orgs: `victim-org` (has `webhook_secret: s3cr3t`, hosts the protected `Team` gating access) and `attacker-org` (no `webhook_secret`, or any org an attacker can get added to the config list).
2. POST to `/github/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": 1, "name": "Core", "slug": "core", "url": "https://github.com/orgs/victim-org/teams/core" },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-github-login" },
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
}
```
No `X-Hub-Signature` header is required since `attacker-org` has no `webhook_secret` → `verify_webhook_signature` returns `true` unconditionally.
3. `MembershipHandler` runs `Team.find_or_create_by!(github_id: 1)` and `team.add_member(User.find_or_create_by_login!('attacker-github-login'))`, creating a `Membership` tying `attacker-github-login` to team id `1`.
4. If `Shipit.github_teams` includes team id `1` (the real gating team), the attacker completes GitHub OAuth as `attacker-github-login` and `current_user.authorized?` now returns `true`, bypassing the intended team-membership authorization boundary.

### Citations

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
```ruby
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

**File:** app/controllers/shipit/github_authentication_controller.rb (L7-21)
```ruby
    def callback
      return_url = request.env['omniauth.origin'] || root_path
      auth = request.env['omniauth.auth']

      return render('failed', layout: false) if auth.blank?

      session[:user_id] = sign_in_github(auth)

      # We need to set this so that the /events and /sidekiq endpoint
      # which leverage `UserRequiredMiddleware` will recognize the user
      # is authenticated.
      session[:authenticated] = true

      redirect_to(return_url)
    end
```
