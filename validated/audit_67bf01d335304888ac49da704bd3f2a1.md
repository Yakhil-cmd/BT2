### Title
Cross-tenant Membership deletion via unscoped `Team.find_or_create_by!(github_id:)` in `MembershipHandler` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` looks up an existing `Team` solely by `github_id`, with no check that the payload's signing organization (`params.organization.login`, the same value used by `WebhooksController#verify_signature`) matches the `Team#organization` already stored on that row. Any organization with a legitimately configured Shipit GitHub App/webhook can therefore forge a `membership` `removed` event naming a team ID that belongs to a different (victim) organization and delete a real operator's `Membership`, de-authorizing them.

### Finding Description
The broken binding, stated explicitly: `params.organization.login` (the org whose webhook secret was used in `verify_signature`) should equal `team.organization` (the org that owns the `Team` row identified by `params.team.id`). This equality is never checked.

Path:
1. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) computes `repository_owner` for a `membership` event as `params.dig('organization', 'login')` (line 61, fallback branch, since `membership` payloads have no `repository` key), and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. This only proves the request was signed with **attacker-org's** own configured secret — it says nothing about which `Team` the payload's `team.id` refers to.
2. `MembershipHandler#process` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`) calls `find_or_create_team!` (lines 38-42):
   ```
   Team.find_or_create_by!(github_id: params.team.id) do |team|
     team.github_team = params.team
     team.organization = params.organization.login
   end
   ```
   The block (which sets `organization`) only runs on **creation**. If a `Team` with that `github_id` already exists (the victim org's real team), it is returned unchanged — its `organization` column still says the victim org, but the request was signed by, and attributed to, the attacker org.
3. `member = User.find_or_create_by_login!(params.member.login)` resolves the victim operator's real `User` row by login.
4. `case params.action; when 'removed' -> team.members.delete(member)` deletes the pre-existing `Membership` row for that user/team pair — regardless of which org signed the request.

Attacker request: an attacker who owns/administers `attacker-org` (with a legitimate Shipit membership webhook already configured, giving them a valid signing secret) POSTs to `/webhooks` with `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with attacker-org's secret, and body:
```json
{
  "action": "removed",
  "team": { "id": <victim_team_github_id>, "name": "...", "slug": "...", "url": "..." },
  "organization": { "login": "attacker-org" },
  "member": { "login": "<victim-operator-login>" }
}
```
`params.team.id` is fully attacker-controlled and is not validated against `params.organization.login`. Existing guards do not catch this: `verify_signature` only authenticates *who signed*, not *which team/org the payload content refers to*; the `ExplicitParameters` schema only checks types/presence, not cross-field/tenant consistency; `Team` has no validation tying `github_id` to `organization` at write time in this code path.

### Impact Explanation
A cross-tenant write: an org that is not the owner of the target `Team` can delete a `Membership` row belonging to a different org's operator, causing `User#authorized?` (`app/models/shipit/user.rb:80-82`) to flip to `false` for that operator if `Shipit.github_teams` includes that team. This is de-authorization of a legitimate operator triggered by an unrelated tenant's webhook — an unauthorized write affecting another party's authorization state, matching the "escalation/interference with `Shipit.github_teams` authorization" High-severity category. It is repeatable against any victim team whose `github_id` the attacker can learn or guess (team IDs are sequential integers on GitHub) and any currently-authorized user's login (logins are public). It does not by itself grant the attacker privileges or RCE, only removes another party's authorization, hence High rather than Critical.

### Likelihood Explanation
Preconditions: attacker must control an organization that already has a legitimately registered Shipit `membership` webhook (a normal, low-cost setup step available to any GitHub org — no Shipit secrets required, since the attacker's own org secret is used for its own signature). Attacker needs the victim `Team`'s GitHub numeric team ID (discoverable via GitHub's public/team APIs or simply guessable, since GitHub team IDs are sequential) and the victim operator's GitHub login (public). No Shipit session, API token, or knowledge of `webhook_secret`/`secret_key_base`/GitHub App key is required — the attacker signs with their own legitimately-issued secret. This is fully repeatable per request and does not require live GitHub interaction to reproduce in tests, since `verify_signature` can be stubbed the same way existing tests do (`Shipit.github(...).expects(:verify_webhook_signature)`).

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that `params.organization.login` matches the existing `team.organization` before performing any add/remove mutation; if they differ, reject the event (e.g., raise/drop with a 422 rather than mutate). Alternatively, scope the lookup itself: `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, ensuring a team row can never be mutated by a payload whose signed organization doesn't match the team's owning organization.

### Proof of Concept
Minitest plan (extending `test/controllers/webhooks_controller_test.rb` style, no live GitHub):
```ruby
test ":membership 'removed' from an unrelated organization cannot delete another org's membership" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify'
  victim_user = shipit_users(:walrus)
  # Precondition: membership exists
  assert Membership.exists?(team: victim_team, user: victim_user)

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'removed',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: 'attacker-org' },
    member: { login: victim_user.login }
  }.to_json

  # Signature verified against attacker-org's own (legitimately configured) secret
  Shipit.github(organization: 'attacker-org').expects(:verify_webhook_signature).returns(true)

  post :create, body: payload, as: :json
  assert_response :ok

  # Broken binding check: organization.login ('attacker-org') != team.organization ('shopify')
  refute_equal 'attacker-org', victim_team.reload.organization

  # Yet the membership was deleted and authorization flipped
  refute Membership.exists?(team: victim_team, user: victim_user)
  refute victim_user.reload.authorized?
end
```
Assert before: `victim_team.organization == 'shopify'` and `Membership.exists?` is true. Assert after: membership deleted and `authorized?` false, despite `params.organization.login ('attacker-org') != victim_team.organization ('shopify')` — proving the provenance binding is not enforced.