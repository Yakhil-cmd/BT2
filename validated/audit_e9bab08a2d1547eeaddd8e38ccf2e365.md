### Title
Membership webhook `team.id` is not scoped to the authenticated organization, allowing cross-tenant escalation into `Shipit.github_teams` authorization - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` proves only that a payload's HMAC matches the webhook secret of *one* GitHub organization (the one named in `repository.owner.login` / `organization.login`). `MembershipHandler` then uses an attacker-supplied `team.id` from that same payload to find-or-create a `Team` record with no check that the team actually belongs to the organization whose secret validated the request. This breaks the intended binding "organization that authenticated == team/repository that is written," letting an attacker who legitimately administers their own (unprivileged, tenant) GitHub organization forge membership events that add themselves to a team belonging to a *different* organization, including a team enumerated in `Shipit.github_teams`.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp` (and its `webhook_secret`) purely from a field inside the same JSON body it is about to verify: [1](#0-0) [2](#0-1) 

This only proves the request was signed by *some* organization's registered secret — the one named by `repository_owner`. It says nothing about any other identifier embedded elsewhere in the payload.

`MembershipHandler#process` then trusts `params.team.id` (an attacker-controlled integer in the JSON body) to look up or create a global `Team` record, without ever checking that this team belongs to `params.organization.login` — the very field that was used to select the verifying secret: [3](#0-2) 

`Team.find_or_create_by!(github_id: params.team.id)` only sets `team.organization = params.organization.login` inside the creation block, i.e. only when the team doesn't already exist. If a `Team` row with that `github_id` already exists (created previously by a legitimate sync for a *different* organization), the block is skipped, the pre-existing team is returned as-is, and `team.add_member(member)` adds the attacker-controlled `member.login` user to it — regardless of which organization's secret validated this request.

This directly parallels the reported bug pattern: a "native" capability (`burnFrom`) that bypasses the contract's intended access restriction because the check covers one binding (approval) but the action operates on an unchecked dimension (arbitrary amount/target). Here, the verified binding is "organization ↔ webhook secret," but the acted-upon binding is "team ↔ organization," which is never re-checked.

### Impact Explanation
`Team` membership is the basis for authorization checks: [4](#0-3) 

If the forged/reused `team.id` corresponds to a team listed in `Shipit.github_teams`, an attacker gains `authorized?` status for the whole Shipit instance without ever having real membership in that team on GitHub — an escalation into `Shipit.github_teams` authorization, matching the "High" impact category defined for this engine (unprivileged escalation into `Shipit.github_teams` authorization).

### Likelihood Explanation
Exploitation only requires the attacker to know the `webhook_secret` of *any* organization registered with this Shipit instance (e.g. their own tenant org, which they configured themselves and therefore legitimately possess), plus the numeric GitHub `team.id` of a target team already synced into Shipit's database (team ids are visible via GitHub's public/team APIs or prior legitimate webhook traffic). No Shipit session, `ApiClient` token, or repository write access is required — the webhook endpoint is unauthenticated aside from the per-organization HMAC. This makes the path realistically reachable for a multi-tenant deployment.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup/update to also match `organization: params.organization.login` (and reject or re-parent teams whose stored `organization` doesn't match), so that a `team.id` collision across organizations cannot be used to attach an attacker to a team owned by a different, unrelated organization. More generally, any handler that looks up shared/global records (`Team`, `User`, `Stack`) by an attacker-suppliable payload id should re-validate that the referenced record's organization/repository matches the organization whose secret authenticated the request.

### Proof of Concept
1. Attacker administers `orgA`, a GitHub organization independently registered with this Shipit instance, and therefore knows `orgA`'s configured `webhook_secret`.
2. A `Team` record already exists in Shipit's database with `github_id = 999` and `organization = "orgB"` (created via a legitimate prior membership sync from `orgB`), and this team's Shipit-side id is included in `Shipit.github_teams`.
3. Attacker crafts a JSON body:
```json
{
  "action": "added",
  "team": {"id": 999, "name": "Owners", "slug": "owners", "url": "https://api.github.com/teams/999"},
  "organization": {"login": "orgA"},
  "member": {"login": "attacker-handle"}
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, body)>` and POSTs it to `/webhooks` with `X-Github-Event: membership`.
5. `verify_signature` resolves `Shipit.github(organization: "orgA")` and validates successfully because the attacker used `orgA`'s real secret [1](#0-0) .
6. `MembershipHandler#find_or_create_team!` finds the pre-existing `github_id: 999` team (belonging to `orgB`) and `team.add_member(member)` adds `attacker-handle` to it [3](#0-2) .
7. If `attacker-handle`'s Shipit `User` is later associated with that `Team`, `User#authorized?` returns `true` due to membership in a `Shipit.github_teams` team the attacker never legitimately joined [4](#0-3) .

Note: I was unable to inspect `app/models/shipit/team.rb` (not returned by the index) to confirm exactly how `Shipit.github_teams` ids map to `Team` records and whether any additional organization check exists elsewhere in the membership/authorization flow. If further confirmation of the exact `Team`/`Shipit.github_teams` mapping is needed, a Devin session with full repository access would be required to read that file in full.

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
