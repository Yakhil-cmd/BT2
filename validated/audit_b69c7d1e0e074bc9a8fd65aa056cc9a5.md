### Title
Cross-org `Team#github_id` binding lets attacker-signed `membership` "removed" webhook silently delete a legitimate `Membership` from another org's team - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#process` deletes a `Membership` (`team.members.delete(member)`) based solely on `params.team.id` and `params.member.login`, without ever confirming that the webhook's signing organization (`params.organization.login`, which drives `verify_signature`) actually owns that `Team`. Since `Team` is looked up only by `github_id` (a globally-unique GitHub team ID, not scoped to organization) and `find_or_create_team!` only sets `organization` on first creation, an attacker who controls a webhook secret for their *own* GitHub org can forge a `membership` "removed" event naming a pre-existing team's `github_id` from a *different* org and a victim's login, causing that user's `Membership` row to be deleted with no corresponding GitHub-side removal.

### Finding Description
Binding claimed: `Membership rows deleted by Shipit == removals GitHub actually reported for that org's team`. This is broken.

Trace:
- `Shipit::WebhooksController#verify_signature` computes `repository_owner` as `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and verifies the signature against `Shipit.github(organization: repository_owner)`'s secret [2](#0-1) . A `membership` payload has no `repository` key, so `repository_owner` becomes `params.organization.login` — the org named in the attacker-controlled payload itself. If the attacker owns/administers that org (or any org configured in Shipit with its own webhook secret), the signature check passes for their own org.
- `MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` [3](#0-2) . If a `Team` with that `github_id` already exists (created earlier for a different, legitimate org), it is fetched as-is; `team.organization` is **not** re-validated or re-set against `params.organization.login`.
- For `action == 'removed'`, the handler runs `team.members.delete(member)` [4](#0-3)  — no call to GitHub, no `refresh_members!`, no comparison between `params.organization.login` and `team.organization`. `Team#members` is a plain `has_many :members, through: :memberships` association [5](#0-4)  with no re-derivation from GitHub.
- Attacker request: attacker who administers Org B (or any org they control, configured with its own webhook secret in Shipit) sends a signed `membership` webhook: `action: 'removed'`, `team: { id: <legitimate-team-id-from-Org-A>, name, slug, url }`, `organization: { login: 'org-b' }`, `member: { login: 'victim' }`. Signature is computed with Org B's own secret and validates for Org B. `find_or_create_team!` finds the existing `Team` row (created for Org A, github_id matching), and the handler deletes `victim`'s membership on that team — even though Org B never had authority over Org A's team.
- Guards checked and found insufficient: `verify_signature` only proves "this request was signed by *some* org's secret", not "this org owns this team ID" — no code cross-checks `team.organization == params.organization.login` before mutating `Memberships`. `ExplicitParameters` schema only validates payload shape, not organizational ownership. `drop_unhandled_event` does not filter by team/org relationship.

Uncertainty: this requires (a) the attacker to control (be an admin of / configure a webhook for) at least one GitHub org that Shipit has a configured `Shipit.github(organization:)` entry for, and (b) knowledge of the numeric `github_id` of the target team belonging to a different org. GitHub team IDs are sequential/enumerable integers exposed via the GitHub API and UI, so this is plausible but requires the target team's ID to be known/guessed — this is a precondition, not a blocker on the code-level vulnerability itself.

### Impact Explanation
Executing this forged webhook deletes a `Membership` row that grants a legitimate user access via `Shipit.github_teams` (used in `User#authorized?` [6](#0-5) ). This is a cross-tenant write: a payload signed for Org B mutates a `Team`/`Membership` record that legitimately belongs to Org A, matching the "payload for one repository/org mutating another's ... team" Critical category, and directly causes de-authorization (denial of legitimate access) which is flagged as a precondition-manipulation step toward broader authorization confusion. Repeatable against any known/guessed team `github_id`, for any victim login, at will, with no GitHub-side corroboration.

### Likelihood Explanation
Requires: (1) attacker administers or controls at least one GitHub organization that Shipit is configured to trust (has a webhook secret entry via `Shipit.github(organization:)`), which is plausible in multi-tenant/self-service GitHub App installations; (2) attacker knows/guesses the numeric `github_id` of the target team in a different org (enumerable, low-cost); (3) the target `Team` row must already exist in Shipit's DB (created from a prior legitimate `added` event) for the "removed" path to find it via `find_or_create_by!`. No Shipit session, token, or secret is required beyond the attacker's own org's webhook signing capability. Feasible and repeatable with a single crafted HTTP POST per victim/team.

### Recommendation
In `MembershipHandler#process`/`find_or_create_team!`, verify that `params.organization.login` matches the `Team#organization` for existing records before performing any add/remove mutation; reject (or log-and-drop) the event if the team's stored organization does not match the webhook's signing organization. Consider re-deriving membership state via `Team#refresh_members!` against GitHub before trusting a "removed" webhook, rather than blindly deleting based on payload content.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/membership_handler_test.rb (conceptual)
test "removed action cannot delete membership on a team belonging to a different signed org" do
  legit_org = "org-a"
  attacker_org = "org-b"
  team = Shipit::Team.create!(github_id: 555, name: "core", slug: "core", organization: legit_org, api_url: "https://api.github.com/teams/555")
  victim = Shipit::User.create!(login: "victim", name: "Victim")
  team.members << victim

  payload = {
    'action' => 'removed',
    'team' => { 'id' => 555, 'name' => 'core', 'slug' => 'core', 'url' => 'https://api.github.com/teams/555' },
    'organization' => { 'login' => attacker_org },   # attacker's own org, signs with org-b's secret
    'member' => { 'login' => 'victim' }
  }

  # Simulate: signature verified successfully for attacker_org (attacker controls org-b's webhook secret)
  Shipit::Webhooks::Handlers::MembershipHandler.new.call(payload)

  # Binding check: Shipit deleted a Membership that GitHub never reported removed for legit_org's team.
  assert_not team.reload.members.include?(victim), "Membership deleted by a webhook signed for a different, non-owning organization"
end
```

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L29-30)
```ruby
          when 'removed'
            team.members.delete(member)
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

**File:** app/models/shipit/team.rb (L7-8)
```ruby
    has_many :memberships
    has_many :members, class_name: :User, through: :memberships, source: :user
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
