### Title
Unauthenticated webhook forgery escalates into `Shipit.github_teams` authorization when a configured organization has no `webhook_secret` — ([File: lib/shipit/github_app.rb])

### Summary
`Shipit::GitHubApp#verify_webhook_signature` treats a blank `webhook_secret` as "signature check passes for everyone", and the organization used to pick *which* app config (and therefore which secret) governs verification is derived directly from the untrusted JSON body of the incoming webhook request. Any organization configured without a `webhook_secret` (an explicitly supported, documented configuration — see `docs/setup.md` "Webhook secret (optional)") becomes an open endpoint: anyone can POST a synthetic `membership` event and have `MembershipHandler` create/modify `Team`/`Membership` records, which is the same set of records `User#authorized?` consults against `Shipit.github_teams`.

### Finding Description
The binding that should hold is:

`organization whose GitHub webhook secret authenticates the request == organization whose events are trusted enough to mutate authorization state (Team/Membership)`

`WebhooksController#verify_signature` selects the app/secret to verify against using data taken from the same unauthenticated payload it is about to verify: [1](#0-0) [2](#0-1) 

The actual signature check then silently no-ops when that resolved organization's config has no `webhook_secret`: [3](#0-2) 

Shipit explicitly supports multiple GitHub organizations each with its own independent config, including an optional (nilable) `webhook_secret` per org, as shown by the fixture/example configs: [4](#0-3) [5](#0-4) 

Once `create` runs, the `membership` event is dispatched, unauthenticated, straight to `MembershipHandler`, which trusts the payload's `team`, `organization`, and `member` fields to create a `Team` and attach a `Membership`: [6](#0-5) 

Because `User#authorized?` and the login gate in `Authentication#force_github_authentication` are built on top of team membership relative to `Shipit.github_teams`: [7](#0-6) 

...an attacker who can freely mint `Membership` rows for a `Team` matching one of `Shipit.github_teams` can grant an arbitrary (already-registered or forged) `User` login authorization to the whole application without ever proving GitHub org/team membership. This mirrors the report's root-cause shape: a field the code trusts for accounting/authorization (`repository.owner.login` deciding which secret gates trust) is not actually bound tightly to the data being trusted and mutated (`organization.login`/`team`/`member` used to write authorization state) — the "collateral" (signature check) does not cover the "debt" (which org's events are safe to process when the org opted out of a secret).

### Impact Explanation
This crosses the required boundary of "escalation into `Shipit.github_teams` authorization" from the impact list: an unprivileged network attacker with zero credentials, no `ApiClient` token, no GitHub App key, and no repository access can forge team/membership state that the application's entire authorization gate relies on, for any organization operator who (per Shipit's own documented setup) chooses not to set a `webhook_secret`. It also allows forging `push`, `status`, and `check_suite` events for that same organization (fake CI green status, fake sync triggers), but the membership-based authorization escalation is the most severe, matching the stated High-severity bucket.

### Likelihood Explanation
Likelihood is conditioned on operator configuration: the `webhook_secret` is documented as optional, so real deployments can legitimately have it unset for one or more configured organizations (multi-org support is a first-class feature per `secrets_double_github_app.yml`). No attacker-side secret, session, or GitHub credential is required — only knowledge of the `/webhooks` endpoint and the target organization's login/team names, which are typically public GitHub metadata. This is not a purely theoretical config; it is the exact fallback path exercised in the codebase's own multi-org test fixtures.

### Recommendation
- Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank; instead, either require a `webhook_secret` for every configured organization at boot/config-validation time, or refuse to process security-sensitive events (`membership`, `push`, `status`, `check_suite`) for organizations lacking a secret.
- Stop deriving the organization used for signature verification from the same untrusted payload being verified; instead, resolve/validate the organization from a value that is itself covered by a fixed, known-good secret (e.g., verify against every configured secret and require the resolved org to match), or require signature verification against every configured app and disambiguate only after a signature validates.
- Treat `MembershipHandler`-driven authorization changes as high-risk and add defense-in-depth (e.g., reconciling `Team`/`Membership` periodically via authenticated GitHub API calls rather than trusting webhook payloads directly for authorization-critical mutations).

### Proof of Concept
1. Operator configures two organizations, `OrgOne` (has `webhook_secret`) and `OrgTwo` (no `webhook_secret`), mirroring `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker (no credentials) sends:
```
POST /webhooks
X-Github-Event: membership
Content-Type: application/json

{
  "action": "added",
  "team": { "id": 999, "name": "Shopify Developers", "slug": "shopify-developers", "url": "https://x" },
  "organization": { "login": "OrgTwo" },
  "member": { "login": "attacker-login" }
}
```
3. `repository_owner` falls back to `params.dig('organization','login')` → `"OrgTwo"` [2](#0-1) ; `Shipit.github(organization: "OrgTwo")` resolves the app config with `webhook_secret: nil`, so `verify_webhook_signature` returns `true` unconditionally [3](#0-2) .
4. `MembershipHandler#process` creates/updates the `Team` and adds `attacker-login` as a member [8](#0-7) .
5. If `attacker-login` is (or later becomes, via normal OAuth login) a Shipit `User`, `current_user.authorized?` now succeeds because of the forged membership, bypassing the intended GitHub-team gate in `force_github_authentication` [7](#0-6) .

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
