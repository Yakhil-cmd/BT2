### Title
Cross-organization Team collision via `github_id` in `MembershipHandler#find_or_create_team!` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#repository_owner` selects the `GitHubApp` (and thus `webhook_secret`) used to verify a webhook based solely on `params.dig('organization', 'login')` when no `repository` key is present, which is the case for `membership` events. `MembershipHandler#find_or_create_team!` then does `Team.find_or_create_by!(github_id: params.team.id)`, an attacker-controlled integer, without ever checking that the found team's `organization` matches the webhook-verified organization, allowing a signed webhook from one (attacker-controlled) organization to mutate a `Team` row belonging to a different organization.

### Finding Description
The intended binding is: **the organization whose `webhook_secret` verified the request == the organization owning the `Team` record that gets mutated**. Concretely: `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` must correspond to `team.organization` for any `Team` written to as a result of that request.

Trace:
- `WebhooksController#verify_signature` picks the `GitHubApp` via `repository_owner`, defined as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` (`app/controllers/shipit/webhooks_controller.rb:59-62`). For a `membership` event, GitHub's real payload (and thus any payload an attacker can freely construct) has no `repository` key, so `repository_owner` resolves purely to `params['organization']['login']`, an attacker-supplied string.
- If the attacker controls (owns) a GitHub organization that is itself configured in Shipit (`Shipit.github(organization: 'attacker-org')` returns a valid `GitHubApp` with a `webhook_secret` the attacker set when creating the webhook for their own org), they can compute a fully valid `X-Hub-Signature` for an arbitrary JSON body, because the signature only proves "signed by the org whose secret this is," not "this payload is about that org."
- `MembershipHandler` (`app/models/shipit/webhooks/handlers/membership_handler.rb:38-43`) resolves the affected team purely from `params.team.id`:
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
```
`find_or_create_by!` only assigns `team.organization` on the **create** branch; if a `Team` row with `github_id == params.team.id` already exists (e.g., a real team belonging to `victim-org`), that existing row is returned unchanged and unchecked against `params.organization.login`.
- `process` (lines 22-33) then does `team.add_member(User.find_or_create_by_login!(params.member.login))`, adding an attacker-chosen GitHub login as a member of that pre-existing `victim-org` team.

Attacker request: send `POST /webhooks` with header `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with the attacker-org's known `webhook_secret`, and body:
```json
{
  "action": "added",
  "team": {"id": 42, "name": "x", "slug": "x", "url": "https://example.com"},
  "organization": {"login": "attacker-org"},
  "member": {"login": "attacker-login"}
}
```
where `42` is the `github_id` of a real `Team` belonging to `victim-org`.

Existing guards do not catch this: `drop_unhandled_event` only checks the event is registered; `verify_signature` only proves the payload was signed by *some* org's secret, not that the org named inside the payload legitimately owns the referenced team; `ExplicitParameters` (`params do ... end` schema) validates types/presence, not cross-org identity; there is no `require_permission!`/authorization check in this controller path since webhooks are inherently "system" actions.

### Impact Explanation
This is an authentication/authorization bypass across tenants: a request that only proves "signed by attacker-org" is used to write a `Membership` row for a `Team` that legitimately belongs to `victim-org`. If that `Team`'s Shipit-side `id` is one of the entries returned by `Shipit.github_teams` (`lib/shipit.rb:256-258`), then `User#authorized?` (`app/models/shipit/user.rb:80-82`) — `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` — will now return true for the attacker's Shipit user, granting them full authenticated access to the Shipit instance (deploys, rollbacks, stack management) that is normally gated to members of `victim-org`'s authorized team. This matches the "escalation into `Shipit.github_teams` authorization" High-severity category. It is repeatable: the attacker can add/remove arbitrary logins from any `Team` row whose `github_id` they can guess or enumerate (small integers, easily brute-forced or discovered via public GitHub team IDs), across any tenant Shipit multi-org configuration.

### Likelihood Explanation
Preconditions: (1) Shipit must be configured in the multi-org mode (`secrets.github` keyed by organization, per `Shipit.github_app_config`) with at least one organization the attacker actually controls (owns/administers) and can set a webhook + `webhook_secret` for; (2) the target `Team.github_id` must be known or guessable (GitHub team IDs are small sequential integers, often discoverable via the GitHub API for public orgs/teams); (3) the target `Team`'s Shipit row `id` must be one of `Shipit.github_teams`. Given multi-tenant Shipit deployments (which is the documented supported mode for this org-keyed config), an attacker who is a legitimate customer/org-owner of one tenant does not need any Shipit credentials, session, or API token — only the ability to sign requests with a secret they themselves configured for their own org. This is a low-cost, fully repeatable attack requiring no privileged Shipit access.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that any existing `Team` found by `github_id` belongs to `params.organization.login` before proceeding (e.g., raise/reject or scope `find_or_create_by!(github_id:, organization: params.organization.login)`), and/or have `WebhooksController#repository_owner`/`verify_signature` cross-check the payload's claimed organization against the actual owning organization for events lacking a `repository` key, ensuring `team.organization == repository_owner` is enforced on every write path, not just the create branch.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "membership webhook cannot join attacker to a team belonging to another organization" do
  victim_team = Shipit::Team.create!(organization: 'victim-org', github_id: 42, name: 'Victim Team', slug: 'victim-team', api_url: 'https://api.github.com/teams/42')

  # Simulate an org the attacker controls, configured in Shipit with a known webhook_secret
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    Shipit::GitHubApp.new('attacker-org', webhook_secret: 'attacker-secret')
  )

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: 42, name: 'x', slug: 'x', url: 'https://example.com' },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker-login' }
  }.to_json
  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', payload)
  @request.headers['X-Hub-Signature'] = signature

  post :create, body: payload, as: :json
  assert_response :ok

  victim_team.reload
  refute victim_team.members.map(&:login).include?('attacker-login'),
    "attacker was added to a Team belonging to a different organization (organization=victim-org, verified_org=attacker-org)"
end
```
Assert the binding explicitly: `victim_team.organization == 'victim-org'` while the request was verified against `'attacker-org'` — these must never diverge for a write to `victim_team` to be legitimate, yet the current code allows exactly that divergence.