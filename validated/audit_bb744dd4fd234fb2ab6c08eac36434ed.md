### Title
Cross-org membership `removed` webhook lets any attacker-controlled organization deopp a Shipit operator - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#process` looks up the target `Team` solely by `params.team.id` (GitHub team ID) via `find_or_create_team!`, without verifying that `params.organization.login` (the org whose signature was actually validated by the controller) matches the `organization` already stored on that `Team` record. Because `Team#github_id` is a GitHub-global numeric ID, and the webhook signature only proves the request came from *some* organization Shipit knows about (the attacker's own), an attacker who registers/owns a GitHub organization wired into Shipit as a `GithubHook::Organization` can send a genuinely-signed `membership` webhook with `action: 'removed'`, guessing/brute-forcing `team.id` for a privileged `Shipit.github_teams` team, and `member.login` set to a real operator's GitHub login, causing `team.members.delete(member)` to delete that operator's `Membership` row for a team they don't administer.

### Finding Description
The broken binding: the code implicitly assumes `params.organization.login == team.organization` (the organization that authorized/signed the webhook equals the organization owning the team being mutated), but this is never checked.

Path:
1. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. This only proves the payload was signed with **the secret belonging to whatever org name appears in the attacker's own payload** — i.e., the attacker's own org, for which they legitimately control the webhook secret because it's their own GitHub org registered with Shipit.
2. `MembershipHandler#process` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`) calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` (lines 38-43) — looked up **only by numeric GitHub team ID**, with no check that `params.organization.login` matches the `organization` field already persisted on that `Team`.
3. For `action == 'removed'`, it runs `team.members.delete(member)` (line 30), removing the `Membership` row for `member = User.find_or_create_by_login!(params.member.login)`.

Attacker request: POST `/webhooks` with header `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with the attacker's own org's registered webhook secret, and body:
```json
{
  "action": "removed",
  "team": { "id": <github_id of a Shipit.github_teams team>, "name": "x", "slug": "x", "url": "http://x" },
  "organization": { "login": "attacker-org" },
  "member": { "login": "victim-operator" }
}
```
Since `Team.github_id` values are GitHub's globally-unique team IDs, and Shipit only trusts the org named in the payload to authenticate the request (not to scope which teams it may mutate), this webhook is accepted, the privileged `Team` matching that `github_id` is resolved, and the victim's `Membership` is deleted — even though the attacker's org has no relationship to that team.

Existing guards checked and found insufficient: `verify_signature` only authenticates the sender org, it does not scope the payload to records owned by that org; `drop_unhandled_event` only checks the event name is handled; the `ExplicitParameters` schema (`params do ... end` in `MembershipHandler`) validates shapes/types only, not ownership; there is no `require_permission!`/authorization check in this handler at all, since it's a github-signed webhook path with an implicit (but here false) assumption of same-tenant binding.

### Impact Explanation
This produces a cross-tenant write: a payload signed by one organization mutates authorization state (`Membership`) belonging to a different, privileged organization's `Team`. `Membership` rows feed directly into `User#authorized?`/team-based deploy authorization checks, so deleting a legitimate operator's membership in a `Shipit.github_teams` team is a targeted, repeatable denial of that specific user's deploy/operator privileges without any Shipit or GitHub credential compromise. This matches "escalation into `Shipit.github_teams` authorization" territory (state corruption of the authorization model), rated High given it doesn't grant the attacker access themselves but corrupts a legitimate operator's access, and is trivially repeatable against any known/guessable team `github_id`.

### Likelihood Explanation
Preconditions: the attacker must control an organization that is already registered with Shipit as a `GithubHook::Organization` (i.e., has installed the Shipit membership webhook and has a corresponding secret) — this can plausibly be any organization onboarded to the Shipit instance for unrelated purposes (e.g., a low-privilege repo owner's own org), since the vulnerability is that `find_or_create_team!` doesn't scope to the requesting org at all. The attacker also needs the victim's GitHub login (public) and the target team's numeric GitHub `id` (discoverable via GitHub's public API for the team, or bruteforceable as small sequential integers). No Shipit session, API token, or GitHub App secret is needed beyond the attacker's own org's webhook secret, which they legitimately possess. This is repeatable at will and works against any team in `Shipit.github_teams`.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization`, and reject/no-op if an existing `Team` with that `github_id` has a different `organization` than `params.organization.login`:
```ruby
def find_or_create_team!
  team = Team.find_by(github_id: params.team.id)
  if team && team.organization != params.organization.login
    raise ArgumentError, "Team #{params.team.id} does not belong to organization #{params.organization.login}"
  end
  team || Team.create!(github_id: params.team.id) do |t|
    t.github_team = params.team
    t.organization = params.organization.login
  end
end
```
Apply the same fix to the `added` path since it shares the identical vulnerable lookup.

### Proof of Concept
minitest (in `test/controllers/webhooks_controller_test.rb`-style, illustrating the missing binding — not asserting current passing behavior, but what should be asserted after the fix, and what currently fails):
```ruby
test ":membership removed webhook signed by unrelated org must not delete membership for a foreign team" do
  team = shipit_teams(:shopify_developers) # organization == 'shopify'
  victim = shipit_users(:walrus)
  Membership.create!(team:, user: victim) unless team.members.include?(victim)

  # Attacker's own org, registered with Shipit, but unrelated to `team.organization`.
  attacker_org = 'attacker-org'
  GithubHook::Organization.create!(organization: attacker_org, event: 'membership', secret: 'attackersecret')
  Shipit.stubs(:github).with(organization: attacker_org).returns(stub(verify_webhook_signature: true))

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'removed',
    team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
    organization: { login: attacker_org },
    member: { login: victim.login }
  }.to_json

  assert_no_difference -> { Membership.where(team:, user: victim).count } do
    post :create, body: payload, as: :json
  end
end
```
Binding checked: LHS `params.organization.login` (`"attacker-org"`) vs RHS `team.organization` (`"shopify"`) — before the fix these are never compared, so the `removed` action succeeds and `Membership.count` for `(team, victim)` decreases; after the fix the mismatch is detected and the deletion is rejected, keeping `Membership.count` unchanged.