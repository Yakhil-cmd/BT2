### Title
Unscoped Team lookup by `github_id` in `MembershipHandler` allows cross-organization membership forgery into `Shipit.github_teams` - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` resolves the target `Team` purely by the attacker-supplied `team.id` field of the webhook JSON body, without checking that the verified webhook organization actually owns that team. Any organization that Shipit has legitimately onboarded (and therefore knows the `webhook_secret` for) can send a validly-signed `membership` event whose `team.id` matches an unrelated organization's already-provisioned `Team` row, causing an arbitrary GitHub login to be granted a `Membership` in that other org's team.

### Finding Description
The broken binding: `Membership(user: X, team: T)` should only ever be created when GitHub itself reports that `X` is a member of `team T`'s real GitHub organization `O`. Instead the code creates it whenever `params.team.id == T.github_id`, with no check that `params.organization.login` (or the verified `repository_owner`) equals `T.organization`.

Path:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) resolves `Shipit.github(organization: repository_owner)` and verifies HMAC using that org's configured `webhook_secret`. This only succeeds for organizations present in `secrets.github` (`lib/shipit.rb:170-181,196-200`) — i.e., organizations Shipit has been explicitly configured/onboarded for, each with its own independently-set `webhook_secret` (`docs/setup.md:30`, `docs/setup.md:181-209`). This is the org's own secret, known to whoever set up that org's GitHub App — not a Shipit-wide secret.
- Once signature verification passes for the attacker's own (legitimately onboarded) organization, `MembershipHandler#process` runs: [1](#0-0) 
- `find_or_create_team!` looks the team up **only by `github_id`**, globally, with no organization scoping: [2](#0-1) 
- Because `Team.find_or_create_by!(github_id: params.team.id)` is unscoped, if a `Team` row with that `github_id` already exists (created earlier from a real event belonging to a *different* organization, e.g. one listed in `Shipit.github_teams`), the block that would set `team.organization = params.organization.login` never executes — the existing (real) `Team`, belonging to the real privileged org, is returned as-is.
- `member = User.find_or_create_by_login!(params.member.login)` (`app/models/shipit/user.rb:22-28`) then fetches/creates a `User` for an arbitrary attacker-chosen login via `Shipit.github.api.user(login)`, using Shipit's own server-side GitHub credentials.
- `team.add_member(member)` (`app/models/shipit/team.rb:41-43`) creates the `Membership` row.
- `User#authorized?` (`app/models/shipit/user.rb:80-82`) and `Authentication#force_github_authentication` (`app/controllers/concerns/shipit/authentication.rb:20-34`) grant application access based solely on `teams.where(id: Shipit.github_teams.map(&:id)).exists?` — i.e., on the forged `Membership` row, with no re-verification against GitHub.

Why existing guards fail: `verify_signature` only authenticates *which organization* sent the event; it never constrains *which team/organization* the payload's `team` object may reference. `find_or_create_team!` has no equality check `params.organization.login == team.organization` (or equivalently, no check that `params.team.id` belongs to the org that GitHub identifies via the verified webhook). The `ExplicitParameters` schema only validates types/presence, not cross-org ownership.

### Impact Explanation
An attacker who controls (or is the legitimate admin of) any single organization onboarded into Shipit's multi-org configuration can grant Shipit-level authorization (membership in any `Shipit.github_teams` team) to an arbitrary GitHub login of their choosing — including logins belonging to uninvolved third parties, or the attacker's own alternate accounts — without that user ever consenting or actually being a GitHub team member of the target org. This also causes Shipit's server-side GitHub token to be used to fetch an arbitrary user's public profile. This is repeatable per targeted `team.id`/`login` pair and constitutes escalation into `Shipit.github_teams` authorization, matching the "High" impact category.

### Likelihood Explanation
Requires: (1) the attacker to control at least one organization already configured in Shipit's `secrets.github` (a legitimate multi-tenant onboarding, not theft of Shipit's own secret), and (2) knowledge/guess of the numeric `github_id` of a privileged `Team` already tracked by Shipit (often derivable from prior legitimate `membership` events, from public team listings, or from small sequential ID ranges). No misconfiguration of Shipit is required beyond normal multi-org support. Cost is a single crafted HTTP POST with a correctly computed HMAC-SHA1 signature using a secret the attacker already legitimately possesses for their own org.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and organization, and reject/ignore events where an existing `Team` with that `github_id` belongs to a different organization than the one verified for this webhook (`repository_owner`/`params.organization.login`). E.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login.downcase)` and explicitly raise/drop the event if a `Team` exists with that `github_id` but a mismatched organization.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/membership_handler_test.rb (conceptual, no live GitHub)
test "membership webhook cannot add members to a team belonging to a different organization" do
  privileged_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: X

  # Attacker's own onboarded org is "attacker-org", verified signature is valid for it.
  payload = {
    action: 'added',
    team: { id: privileged_team.github_id, name: 'Developers', slug: 'developers', url: 'http://example.com' },
    organization: { login: 'attacker-org' },
    member: { login: 'innocent-third-party' },
    repository: { owner: { login: 'attacker-org' } }
  }

  Shipit.github.api.expects(:user).with('innocent-third-party').returns(
    stub(id: 999, login: 'innocent-third-party', name: 'Innocent', email: nil, avatar_url: '', url: '')
  )

  assert_no_difference -> { Shipit::Team.count } do
    assert_difference -> { Shipit::Membership.count }, 0 do # EXPECTED after fix; currently +1, proving the bug
      Shipit::Webhooks::Handlers::MembershipHandler.new(payload.deep_stringify_keys).call
    end
  end

  refute privileged_team.members.exists?(login: 'innocent-third-party')
end
```
Before the fix, this test demonstrates `Membership.count` increasing by 1 and `privileged_team.members` including `innocent-third-party`, i.e. `params.team.id == privileged_team.github_id` binds to `privileged_team` even though `params.organization.login ('attacker-org') != privileged_team.organization ('shopify')`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```
