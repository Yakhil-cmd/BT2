### Title
Unauthenticated forged webhook can grant arbitrary GitHub-team authorization when an organization's `webhook_secret` is unset - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration to use for HMAC validation based on an *organization* value taken straight from the unauthenticated request body, then hands the same unauthenticated body to event handlers that write authorization-relevant state (`Team`/`Membership`) verbatim. When the selected organization's `webhook_secret` is not configured (an explicitly supported, documented state), signature verification becomes a no-op, so the "organization that authenticated" and "the data that gets written" are never actually bound to a real GitHub-signed payload.

### Finding Description
`verify_signature` derives the app/organization to validate against purely from the payload itself: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

The signature check itself is a no-op whenever that organization's app config has no `webhook_secret` set: [3](#0-2) 

```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

`webhook_secret` is documented as optional/nullable per organization (`webhook_secret: # nil`), including in multi-org setups: [4](#0-3) [5](#0-4) 

Once verification passes (trivially, because `webhook_secret` is nil for the org named in the attacker-chosen payload), the raw, otherwise-unauthenticated body is dispatched to handlers. `MembershipHandler` trusts `team`, `organization`, and `member.login` directly from that body to create a `Team` and add a `User` as a member, with no cross-check against the real GitHub API state: [6](#0-5) 

That membership directly controls Shipit's authorization gate: [7](#0-6) [8](#0-7) 

```
def authorized?
  @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
end
```

**Binding broken:** the organization value used to select/authenticate the webhook (`repository_owner` → `Shipit.github(organization:)` → `verify_webhook_signature`) is not actually cryptographically bound to the request when that organization has no `webhook_secret`, yet the same request's `team`/`organization`/`member` fields are written straight into `Shipit.github_teams` membership state that gates login authorization (`User#authorized?`). "Organization that authenticated" ≠ "data that is written," because for that organization no authentication occurred at all.

### Impact Explanation
This maps to the explicitly allowed High-impact class: "escalation into `Shipit.github_teams` authorization." An attacker who knows (a) the name of any organization configured in `secrets.yml` without a `webhook_secret`, and (b) the numeric `team.id`/`slug` of a `Shipit.github_teams`-restricted team belonging to a *different, properly secured* organization, can POST a forged `membership` event to `/webhooks` claiming `action: added` for an arbitrary GitHub login. `MembershipHandler` will create/find that `Team` by `github_id` and add a `User` record (created purely from the attacker-supplied login string) as a member — with no verification of the claim against the real GitHub API. If the attacker's own GitHub login matches (or they later authenticate as that user via the legitimate GitHub OAuth flow, which only checks `login_id`/`github_id`), `current_user.authorized?` becomes true and the attacker gains full access to the Shipit application (viewing task output, deploying, rolling back, etc. per `Shipit.github_teams` gating).

### Likelihood Explanation
Requires no privileged credential: no Shipit session, `ApiClient` token, `webhook_secret`, `api_clients_secret`, GitHub App private key, or repository write access is needed by definition of the bug (that's exactly what's missing). The only precondition is an operator configuration where some organization entry lacks `webhook_secret` — a state explicitly supported and shown as the default in `config/secrets.development.example.yml`. Organization names are public, and the `X-Github-Event: membership` header/body shape is documented and easily crafted.

### Recommendation
- Do not select the verification key from unauthenticated payload data; verification must not silently succeed when `webhook_secret` is absent for the org resolved from that same untrusted payload — refuse (422) instead of `return true`.
- Cross-check `membership`/other event payload contents against a live GitHub API call before mutating `Team`/`Membership` records that gate authorization, rather than trusting the webhook payload verbatim.

### Proof of Concept
1. In `secrets.yml`, configure a multi-org setup where `attacker-org` has `webhook_secret: nil` (a supported, documented state) but `secure-org` uses `Shipit.github_teams` for authorization gating (e.g. `Shipit/team`, github team id `123`).
2. POST to `/webhooks` with header `X-Github-Event: membership` and no/garbage `X-Hub-Signature`, body:
```json
{
  "action": "added",
  "team": { "id": 123, "name": "team", "slug": "team", "url": "https://api.github.com/teams/123" },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-github-login" }
}
```
3. `repository_owner` resolves to `attacker-org` (via `params.dig('organization','login')`), `Shipit.github(organization: 'attacker-org').verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is nil for that org.
4. `MembershipHandler#process` finds/creates `Team` with `github_id: 123` (which is the real, secure `Shipit/team`), creates `User` with login `attacker-github-login`, and calls `team.add_member(member)`.
5. Attacker completes normal GitHub OAuth login as `attacker-github-login`; `current_user.authorized?` now returns `true` because that `User` record has team membership in `Shipit.github_teams`, granting full application access without ever being a real member of the secure GitHub team.

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

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
