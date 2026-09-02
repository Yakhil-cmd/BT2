### Title
Cross-organization team hijack via unscoped `Team.find_or_create_by!(github_id:)` in `MembershipHandler#process` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` resolves a `Team` record solely by `params.team.id` (GitHub's numeric team ID), with no check that `params.organization.login` matches the `organization` already stored on that `Team`. `WebhooksController#verify_signature` legitimately proves the payload came from whatever organization is named in `params.organization.login`, but the handler never re-validates that this authenticated organization actually owns the `Team` row it is about to mutate, letting one Shipit-configured tenant modify a team belonging to another tenant.

### Finding Description
The binding that must hold is: `authenticated_org (params.organization.login, verified via Shipit.github(organization: repository_owner).verify_webhook_signature)` == `team.organization (the organization that originally owned/created this Team row)`.

Trace:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` and fetches `Shipit.github(organization: repository_owner)` to verify the HMAC signature. For a `membership` event this is `params.organization.login`, so a valid signature only proves the request came from whichever organization the *attacker's own payload* names in `organization.login` — it says nothing about the `team.id` field. [1](#0-0) [2](#0-1) 
- `MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }`. The block that sets `organization` only runs when a **new** record is created; if a `Team` with that `github_id` already exists (e.g. previously created for a legitimate, different organization), it is returned unchanged, and `params.organization.login` from the current (attacker-authenticated) payload is silently discarded. [3](#0-2) 
- `team.add_member(member)` / `team.members.delete(member)` (`app/models/shipit/team.rb:41-43`) is then executed against that pre-existing team with no re-check of `team.organization` against the requesting org. [4](#0-3) 
- `User#authorized?` gates the entire engine on membership in `Shipit.github_teams`, which is populated from configured `oauth.teams` handles and looked up by `Team` identity (`Shipit.github_teams` builds/caches these `Team` records). [5](#0-4) [6](#0-5) 

Exploit flow (requires a Shipit deployment configured with multiple GitHub organizations/tenants sharing one instance, as the codebase explicitly supports via `secrets.github.<org>.webhook_secret` per org): an attacker who controls (or is a member of) one configured tenant organization ("attacker-org") sends a correctly-signed `membership` webhook using attacker-org's own `webhook_secret`, but sets `team.id` to the GitHub numeric ID of a `Team` row already tracked for a different ("victim") tenant that is listed in `Shipit.github_teams`, and sets `member.login` to an arbitrary GitHub login (their own, or an accomplice's). `Team.find_or_create_by!` matches the existing victim team by `github_id` alone, and `team.add_member` inserts a `Membership` linking the attacker-chosen user to the privileged team — without ever needing the victim org's `webhook_secret`.

Existing guards do not prevent this: `verify_signature` only proves the identity of the organization *named in the payload*, not that this organization owns the specific `team.id` referenced; there is no `ExplicitParameters` or model-level check binding `Team#organization` to the webhook's authenticated organization on lookup.

### Impact Explanation
This is a direct escalation into `Shipit.github_teams` authorization (the "High" category explicitly listed): an attacker with control of any one Shipit-configured tenant organization can add an arbitrary GitHub login as a member of a privileged `Team` belonging to a different tenant, making that login `authorized?` across the whole engine (deploy/rollback/merge access, depending on how the host app gates these features on `authorized?`). The attack is repeatable for any `Team` whose `github_id` the attacker can determine, and blast radius spans every tenant sharing the Shipit instance, not just the attacker's own org.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment where the attacker legitimately controls or belongs to at least one configured GitHub organization (webhook_secret known to them, e.g. as an org admin who installed the Shipit GitHub App), and (2) knowledge of the victim `Team`'s GitHub numeric `github_id`, which is not guaranteed to be publicly enumerable (visible generally only to org members/admins or via GitHub team APIs, though it is a low-cardinality integer and could leak via logs, prior webhook deliveries, or other observation). Given the stated threat-model assumption of a victim org existing and the team ID being "attacker-guessable/observable," this precondition is treated as satisfiable; the core code defect — missing re-validation of `Team#organization` on lookup — is real and independent of exactly how the ID is obtained.

### Recommendation
In `find_or_create_team!`, validate that an existing `Team` found by `github_id` has `organization == params.organization.login` before allowing `add_member`/`delete`; raise/reject (e.g. head 422) on mismatch instead of silently reusing the record. Alternatively, scope the lookup by both `github_id` and `organization` (`find_or_create_by!(github_id:, organization: params.organization.login)`), so a payload from one organization can never match a `Team` row created for another.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/membership_handler_test.rb`):
1. Fixture: create/use `shipit_teams(:shopify_developers)` with `github_id: 1`, `organization: 'shopify'`, matching an entry returned by `Shipit.github_teams` (as in `test/models/users_test.rb` "authorized? if part of Shipit.github_teams").
2. Configure a second org `attacker_org` in `Shipit.github` test config with its own `webhook_secret`.
3. Build a membership payload: `{ action: 'added', team: { id: 1, name: 'Shopify Developers', slug: 'shopify-developers', url: '...' }, organization: { login: 'attacker_org' }, member: { login: 'mallory' } }`, signed with `attacker_org`'s webhook_secret (matching what `verify_signature` expects for `repository_owner = 'attacker_org'`).
4. POST to `/webhooks` with `X-Github-Event: membership` and the correct `X-Hub-Signature` for `attacker_org`.
5. Assert response is `:ok`, and assert `Membership.exists?(team: shipit_teams(:shopify_developers), user: shipit_users(where login: 'mallory'))` — i.e. `Team.find(shipit_teams(:shopify_developers).id).members.map(&:login)` includes `'mallory'`.
6. Assert `User.find_by(login: 'mallory').authorized?` is `true` given `Shipit.stubs(:github_teams).returns([shipit_teams(:shopify_developers)])`, proving the attacker escalated an arbitrary login into `shopify`'s authorized-team membership despite authenticating only as `attacker_org`.

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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```
