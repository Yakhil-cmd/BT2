### Title
Membership Webhook Team-Binding Bypass Allows Unauthorized Escalation into `Shipit.github_teams` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to validate a request against using an attacker-controlled field of the *same* unauthenticated payload, and that secret is optional/nilable per the documented config schema. Once past signature verification, `MembershipHandler` binds the webhook's `team` payload to an existing `Team` record using only the GitHub numeric `team.id`, never re-checking that the claimed `organization.login` in the (now "verified") payload actually matches the organization of the team being mutated. This breaks the intended binding "organization that authenticated" == "team/organization actually written," letting an attacker who can satisfy verification for *any* configured org add arbitrary GitHub logins to a `Team` that is unrelated to that org — including a team used by `Shipit.github_teams` for authorization.

### Finding Description
Signature verification is performed here: [1](#0-0) 

`repository_owner` (used to pick the `github_app`/secret) is extracted straight from the untrusted payload: [2](#0-1) 

`verify_webhook_signature` treats a missing `webhook_secret` as automatically verified: [3](#0-2) 

The webhook secret is explicitly documented as optional, and multi-org setups are a supported, documented configuration schema where different organizations can have different (or blank) secrets: [4](#0-3) 

Once the request passes this check, `MembershipHandler#process` mutates team membership by looking the `Team` up **only by GitHub's numeric `team.id`**, never validating that `params.organization.login` corresponds to the team actually being modified: [5](#0-4) 

The `organization` field is only ever written when the `Team` record is newly created (inside the `find_or_create_by!` block); for any pre-existing `Team` (which is exactly the case for teams already used in `Shipit.github_teams`, since those are fetched/created at boot via `Team.find_or_create_by_handle`), the `organization.login` supplied in the payload is completely ignored for authorization purposes on the update path.

`Shipit.github_teams` and `User#authorized?` rely on `Team` membership for access control: [6](#0-5) [7](#0-6) 

**The binding that is broken:** the organization whose (possibly-absent) secret was used to pass `verify_signature` ≠ the organization/team that `MembershipHandler` actually mutates. `verify_signature` only proves the raw body is unmodified relative to *some* configured org's secret (or nothing, if that org has no secret); it proves nothing about which `Team` record the payload is allowed to touch. `MembershipHandler` never re-derives or checks that binding, trusting `team.id` alone.

### Impact Explanation
An attacker who can satisfy signature verification for any one configured GitHub organization (trivial if that organization has no `webhook_secret` configured, which the setup docs present as optional) can send a forged `membership` webhook naming any pre-existing `Team.github_id` — including the `Team` backing one of `Shipit.github_teams` — and add an arbitrary GitHub login as a member:

```ruby
team.add_member(member)  # member = User.find_or_create_by_login!(params.member.login)
```

If the attacker then authenticates via the standard GitHub OAuth login flow using that same GitHub login, `User#authorized?` will resolve to `true` because the user is now a member of a team in `Shipit.github_teams`, granting full access to the Shipit instance (viewing/triggering deploys, rollbacks, creating API clients, etc.). This is a direct escalation into `Shipit.github_teams` authorization, matching the explicitly listed High-impact category.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment where at least one configured organization has a blank `webhook_secret` — a state the project's own example/documentation presents as normal/optional — or otherwise knowledge of one org's secret, and (2) knowledge/guessing of the numeric GitHub `team.id` for the trusted, already-provisioned team (a small, often-enumerable integer, and potentially visible via GitHub's own API/UI for the target org). No repository write access, GitHub App private key, or Shipit session is needed to reach the `/webhooks` endpoint itself, which is unauthenticated by design (it's the GitHub webhook receiver).

### Recommendation
- In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization` (downcased), and reject the event (or refuse to mutate the team) if an existing `Team` with that `github_id` belongs to a different organization than `params.organization.login`.
- Additionally, cross-check that the `organization.login` used to select the verification secret in `WebhooksController#verify_signature` matches the `organization.login` inside the event payload being processed, so verification and processing are bound to the same organization.
- Discourage/deprecate configuring an empty `webhook_secret` for any organization used to protect authorization-relevant teams; consider making it mandatory in multi-org setups.

### Proof of Concept
1. Deploy Shipit with a multi-org `github` config where organization `noauth-org` has `webhook_secret: nil` and organization `trusted-org` is the source of a team listed in `oauth.teams` (e.g. `trusted-org/admins`, whose `Team` row has `github_id: 999`).
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "admins", "slug": "admins", "url": "https://api.github.com/..." },
  "organization": { "login": "noauth-org" },
  "member": { "login": "attacker-github-login" }
}
```
No valid `X-Hub-Signature` is required because `noauth-org` has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally.
3. `MembershipHandler` looks up `Team.find_or_create_by!(github_id: 999)`, finds the pre-existing `trusted-org/admins` team (ignoring that the payload claims `noauth-org`), and calls `team.add_member(User.find_or_create_by_login!("attacker-github-login"))`.
4. Attacker logs in via GitHub OAuth as `attacker-github-login`; `current_user.authorized?` now returns `true`, granting full access to the Shipit instance.

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

**File:** config/secrets.development.example.yml (L18-38)
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
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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
