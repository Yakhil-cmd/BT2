### Title
Cross-organization Team hijack via `github_id`-only matching in membership webhook handler bypasses `Shipit.github_teams` authorization - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::MembershipHandler#find_or_create_team!` looks up (or creates) a local `Team` record using only the GitHub-global `team.id` field from the inbound webhook payload, without checking that the `organization.login` in the payload matches the `Team#organization` already stored for that `github_id`. The inbound webhook signature only proves *which organization's secret* signed the request, not that the `team`/`organization` fields inside the JSON body correspond to that same organization's team. An attacker who legitimately administers an unrelated GitHub organization onboarded onto the same multi-tenant Shipit instance can forge a `membership` webhook, correctly signed with their own org's `webhook_secret`, but referencing the numeric `team.id` of a privileged team belonging to a different organization (e.g. one listed in `Shipit.github_teams`). This adds an attacker-controlled GitHub login to that privileged `Team`'s `Membership` records, without ever touching the victim organization's real GitHub team.

### Finding Description
The webhook signature check in `WebhooksController#verify_signature` selects the `github_app`/secret to validate against based on `repository_owner` (i.e. `organization.login` for membership events), then verifies the raw body HMAC against that org's configured `webhook_secret`. [1](#0-0) [2](#0-1) 

This proves only that *the organization named in the payload owns the secret used to sign the request* — it says nothing about whether the `team` object embedded in that same payload actually belongs to that organization. `MembershipHandler` then does: [3](#0-2) 

`find_or_create_team!` calls `Team.find_or_create_by!(github_id: params.team.id)`. If a `Team` row with that `github_id` already exists (e.g. previously synced through `bin/rake teams:fetch` for an org referenced in `Shipit.github_teams`), the block that sets `team.organization = params.organization.login` is **not** executed (it only runs on record creation), and the existing team is returned as-is. The handler then unconditionally does `team.add_member(member)` where `member` is resolved purely from the attacker-controlled `member.login` string via `User.find_or_create_by_login!`. [4](#0-3) 

The equality that should hold but doesn't:
`organization that authenticated the request (secret owner)` == `organization that owns the team being written to (params.team.id owner)`.
The handler enforces the first (via the controller's signature check) but writes based solely on the second's numeric ID, with no cross-check.

Because `User#authorized?` grants access purely from local DB `Membership` rows against `Shipit.github_teams`, this write directly grants Shipit access: [5](#0-4) 

### Impact Explanation
This is a direct escalation into `Shipit.github_teams` authorization — explicitly one of the High-impact categories in scope. An attacker who is merely an admin of *any* GitHub organization onboarded to the shared Shipit instance (and thus legitimately knows that org's own `webhook_secret`, which they configured themselves) can grant an arbitrary GitHub login membership in a privileged team belonging to a completely different, victim organization, without any actual GitHub-side team change and without any Shipit session, `ApiClient` token, or the victim organization's secret.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured for multiple GitHub organizations (a documented, supported configuration per `secrets.development.example.yml`), (2) the attacker administers one of those organizations (an unprivileged position with respect to Shipit itself and the victim org/repo), and (3) knowledge of the victim's privileged `Team`'s numeric GitHub `github_id`, which is discoverable via GitHub's public/organization API (`GET /orgs/{org}/teams`) if the attacker can see the team, or by brute-forcing since team IDs are sequential integers. No repository write access, TLS interception, or victim secret is needed.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization` (i.e. require `team.organization == params.organization.login`), and reject/raise if an existing team with that `github_id` belongs to a different organization than the one that authenticated the webhook. More generally, `WebhooksController#verify_signature` should bind the verified organization to every subsequent DB write inside handlers, not just to secret selection.

### Proof of Concept
1. Shipit instance is configured with `github:` entries for both `OrgA` (victim, referenced by `Shipit.github_teams: [OrgA/restricted]`) and `OrgB` (attacker-administered).
2. `OrgA/restricted` team is already synced into Shipit's `teams` table with `github_id = 555` (via `bin/rake teams:fetch` or an earlier legitimate `membership` event).
3. Attacker, an admin of `OrgB`, knows `OrgB`'s `webhook_secret` (they configured it) and crafts:
```json
{
  "action": "added",
  "team": { "id": 555, "name": "restricted", "slug": "restricted", "url": "https://api.github.com/teams/555" },
  "organization": { "login": "OrgB" },
  "member": { "login": "attacker-controlled-login" }
}
```
4. Attacker computes `X-Hub-Signature` with `OrgB`'s secret and POSTs to `/webhooks`. `verify_signature` passes (organization = OrgB, secret matches).
5. `MembershipHandler#process` finds existing `Team(github_id: 555)` (which is `OrgA/restricted`) and calls `team.add_member(User.find_or_create_by_login!("attacker-controlled-login"))`.
6. `attacker-controlled-login`'s Shipit `User` now has a `Membership` in `OrgA/restricted`, and `User#authorized?` returns `true` for `Shipit.github_teams` checks — full authenticated access to the Shipit instance — despite never being added to the real GitHub team.

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
