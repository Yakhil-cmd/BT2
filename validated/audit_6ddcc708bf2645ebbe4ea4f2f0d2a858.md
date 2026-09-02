### Title
Webhook signature bypass allows forged `membership` events to grant `Shipit.github_teams` authorization to any GitHub-authenticated attacker - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to validate the HMAC signature against, based on a payload-controlled field (`repository.owner.login`, falling back to `organization.login`). `GitHubApp#verify_webhook_signature` treats a blank/unconfigured `webhook_secret` as automatic success (`return true unless webhook_secret`). Because `webhook_secret` is documented as optional per-organization, any organization entry in the multi-org config without a secret configured becomes a universal bypass: an attacker can pick that organization's name for the `organization`/`repository.owner.login` field to skip signature verification entirely, while still supplying a `membership` event payload whose `team`/`organization`/`member` fields reference a *different*, privileged organization/team tracked by Shipit. `MembershipHandler` will then create/find that team and add the attacker-chosen GitHub login as a member, with no check that the authenticated organization matches the organization referenced inside the event body.

### Finding Description
The binding that should hold is: **the organization whose signature validated the request == the organization/team the event payload authorizes changes for**. This binding is broken:

- `WebhooksController#verify_signature` picks the app config purely from attacker-supplied payload fields: [1](#0-0) [2](#0-1) 

- `GitHubApp#verify_webhook_signature` unconditionally trusts the request when no secret is configured for that organization: [3](#0-2) 

- The setup docs explicitly mark `webhook_secret` as optional per org, and the multi-org example config shows it can be left blank per organization: [4](#0-3) [5](#0-4) 

- `MembershipHandler` never re-validates that `params.organization.login` matches the organization that authenticated the webhook (the value used in `verify_signature`). It simply creates/finds a `Team` by the payload's `team.id`/`organization.login` and adds the payload's arbitrary `member.login`: [6](#0-5) 

- `Shipit.github_teams` (the authorization gate) is built directly from `Team` records matched by organization/slug handle, and `User#authorized?` simply checks team membership: [7](#0-6) [8](#0-7) [9](#0-8) 

Exploit flow:
1. Shipit is configured with a multi-org GitHub App setup where at least one org (`org-with-no-secret`) has no `webhook_secret` set (allowed by the documented config schema).
2. Attacker signs in through the normal GitHub OAuth flow (`GithubAuthenticationController#callback`) with their own, otherwise-unprivileged GitHub account, obtaining a Shipit session/`User` record but failing `authorized?` (not a member of `Shipit.github_teams`): [10](#0-9) [11](#0-10) 
3. Attacker POSTs directly to `/webhooks` with header `X-Github-Event: membership` and a JSON body: `{"action":"added","organization":{"login":"org-with-no-secret"},"team":{"id":<real_id_of_privileged_team>,"name":"Developers","slug":"developers","url":"..."},"member":{"login":"<attacker-github-login>"}}`.
4. `repository_owner` resolves to `"org-with-no-secret"` (no `repository` key present, falls back to `organization.login`), causing `Shipit.github(organization: "org-with-no-secret")` to be used, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — no valid `X-Hub-Signature` is required at all.
5. `MembershipHandler#process` finds the real privileged `Team` (matched by `github_id`) and calls `team.add_member(User.find_or_create_by_login!("<attacker-github-login>"))`, adding the attacker as a member of that team even though the org used to bypass signature verification is unrelated to the privileged team's organization.
6. On the attacker's next request, `User#authorized?` now returns true because `teams.where(id: Shipit.github_teams.map(&:id)).exists?` matches, granting them access to all Shipit stacks gated by `force_github_authentication`.

### Impact Explanation
This is a direct authentication/authorization bypass: an attacker who only possesses a standard (unprivileged) GitHub identity can escalate into `Shipit.github_teams` authorization without ever needing a valid webhook secret, a Shipit session token, or repository write access — matching the explicitly listed High-severity impact "escalation into `Shipit.github_teams` authorization." Once authorized, the attacker gains full application access (viewing stacks, triggering deploys/rollbacks/tasks subject to further permission checks that are themselves gated on being a "member"), which can cascade toward unauthorized deploys.

### Likelihood Explanation
Likelihood depends on operational configuration: it requires (a) a multi-org GitHub App configuration (documented and supported) and (b) at least one configured organization lacking a `webhook_secret` (explicitly documented as "optional"). Given the setup docs present this as a normal, supported configuration pattern and do not warn that an org-level missing secret disables verification for *all* event types system-wide (including cross-organization `membership`/`push` events), this is a realistic misconfiguration rather than a contrived edge case. The `WebhooksController` also has no requirement that the org used for verification matches the org referenced inside `team`/`repository` payload fields, so the flaw is present regardless of which org's secret is missing.

### Recommendation
- Do not let a missing `webhook_secret` for a single organization silently disable signature verification; treat it as a hard misconfiguration (raise/fail closed) rather than falling back to "verified".
- In `MembershipHandler` (and other handlers keyed on `organization`/`repository`), assert that the payload's `organization.login`/`repository.owner.login` matches the organization/app config that was used to verify the signature (`repository_owner` computed in `WebhooksController`), rejecting the event otherwise.
- Consider requiring `webhook_secret` to be mandatory for all configured organizations in the multi-org schema.

### Proof of Concept
```
POST /webhooks HTTP/1.1
X-Github-Event: membership
Content-Type: application/json

{
  "action": "added",
  "organization": { "login": "org-with-no-secret" },
  "team": { "id": 48, "name": "Developers", "slug": "developers", "url": "https://example.com" },
  "member": { "login": "attacker-github-login" }
}
```
No `X-Hub-Signature` header (or any arbitrary value) is required, because `Shipit.github(organization: "org-with-no-secret")` resolves to a `GitHubApp` whose `webhook_secret` is blank, causing `verify_webhook_signature` to return `true` unconditionally [3](#0-2) 
. `MembershipHandler#process` then adds `attacker-github-login` to team id `48` (an arbitrary, real, privileged team) regardless of which organization actually owns that team [6](#0-5) 
.

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

**File:** config/secrets.development.example.yml (L18-34)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
```

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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
