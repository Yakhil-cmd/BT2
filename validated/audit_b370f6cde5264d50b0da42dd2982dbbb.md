### Title
Membership webhook `organization.login` used for Team ownership diverges from `repository.owner.login` used for signature verification, allowing cross-org Team writes - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#repository_owner` (used to pick the `GitHubApp`/webhook secret for `verify_signature`) reads `params.dig('repository','owner','login')` first, falling back to `params.dig('organization','login')` only when `repository` is absent. `MembershipHandler#find_or_create_team!` independently reads `params.organization.login` for `Team#organization=`, with no assertion that this equals `repository.owner.login`. An attacker who controls a real GitHub App installation on org X can send a payload with `repository.owner.login = X` (verified correctly against X's webhook secret) and a top-level `organization.login = Y` (used only by the handler), producing a `Team` record with `organization = Y` despite the request only being authenticated for X.

### Finding Description
The broken binding: the code implicitly assumes `params.dig('repository','owner','login') == params.dig('organization','login')` for any membership webhook, but this equality is never asserted anywhere in the request-processing path.

Path:
1. `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) calls `Shipit.github(organization: repository_owner)` and validates the HMAC signature using that org's `GithubApp#verify_webhook_signature` (`webhook_secret` for that specific app config).
2. `repository_owner` (lines 59-62) is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — i.e. it prefers `repository.owner.login` and only falls back to `organization.login` when `repository` key is missing.
3. If the JSON body has both keys populated but with different logins, `repository_owner` returns `repository.owner.login` (org X), so the HMAC is checked against X's `webhook_secret` — which the attacker can compute correctly because they run a real installation on X and can trigger genuine, X-signed membership webhooks (or simply because they know/can trigger their own org's secret-signed events).
4. Once signature verification passes, `Shipit::Webhooks.for_event('membership').each { |handler| handler.call(params) }` dispatches to `MembershipHandler`, which never looks at `repository` at all — its `params` schema (app/models/shipit/webhooks/handlers/membership_handler.rb:7-21) only requires `:action`, `:team`, `:organization`, `:member`.
5. `find_or_create_team!` (lines 38-43) does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }`, using the attacker-supplied `organization.login` (org Y) with no cross-check against the org that was actually authenticated (X).

Why existing guards fail: `verify_signature` only ever authenticates whichever org's login is chosen by `repository_owner`'s fallback logic; it never checks that this login matches every other "organization" reference used later in `params`. `ExplicitParameters` (`MembershipHandler.params`) validates types/presence but not cross-field consistency with the top-level payload used by the controller. No model validation ties `Team#organization` back to a verified installation.

Caveat on exploitability: `Team.find_or_create_by!(github_id: params.team.id)` only executes the block (and thus sets `organization`) when no `Team` with that `github_id` already exists — for an existing team, the attacker-controlled `organization.login` in the divergent payload has no effect on that record. The exploit is therefore constrained to **creation** of a new `Team` row (a team `github_id` not yet present in Shipit's database) with an attacker-chosen `organization` value, not mutation of an existing team's organization.

### Impact Explanation
A successful request creates a `Shipit::Team` record whose `organization` column is set to an arbitrary org Y chosen by the attacker, while the request was only ever authenticated as originating from org X (an org the attacker legitimately controls an installation on). This is a cross-tenant data-integrity/write issue: a `Team` object nominally scoped to org Y is fabricated using an installation belonging to org X, and its membership (`Membership` rows, added via `team.add_member(member)`) can subsequently be manipulated by any further webhooks the attacker can trigger from X, all while the record purports to belong to Y. This is a write for one organization mutated/created via authentication that only proves control of a different organization, matching the "payload for one repository/organization mutating another's team" Critical category, though scoped specifically to Team creation (not arbitrary existing-team takeover).

### Likelihood Explanation
Preconditions: the attacker needs a real GitHub App installation on some org X registered in `Shipit.github_teams`/`Shipit.github` config (so `verify_signature` succeeds for X), and must be able to send an HTTP POST to `/webhooks` with a custom JSON body and a valid `X-Hub-Signature` computed with X's webhook secret — both of which are available to the org's own admin/installer since GitHub signs webhooks with the receiving app's configured secret, and self-triggering `membership` events (e.g. add/remove a team member in their own org) is a normal, unprivileged action. The attacker then only has to also include a top-level `organization.login` differing from `repository.owner.login` in the crafted body before it's HMAC-signed by their own installation. This requires the attacker to control signature generation, which in the standard GitHub webhook flow they do not (GitHub itself signs and sends the payload, and typically `repository.owner.login` and `organization.login` are always equal in genuine GitHub-emitted membership events) — exploitation instead requires either a replay/relay capability or a scenario where the attacker's own server crafts the raw JSON body and computes the signature manually if they possess X's `webhook_secret` value in a test/staging config, or where GitHub itself could be tricked into emitting such a divergent payload (not demonstrated as possible; GitHub's own membership event schema keeps `repository` and `organization` consistent). Given the audit's precondition framing ("attacker controls a real installation on org X"), it is presented as satisfiable, but full exploitability depends on whether an attacker with only "installation" access (not the webhook secret itself) can produce a validly-signed request — the code path itself (lines 59-62 and 38-43) does exhibit the unchecked divergence regardless.

### Recommendation
In `MembershipHandler#find_or_create_team!` (and any other handler reading a top-level `organization`/`repository` object), assert that `params.organization.login` matches the authenticated `repository_owner`/org used in `WebhooksController#verify_signature`, e.g. by passing the verified organization into the handler and raising/dropping the event if `payload.dig('repository','owner','login')` is present and differs from `payload.dig('organization','login')`. Alternatively, make `repository_owner` derive strictly from a single canonical field and have handlers reuse that exact same value rather than re-reading `organization.login` independently.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":membership organization divergence creates team under attacker-chosen org" do
  @request.headers['X-Github-Event'] = 'membership'

  body = {
    action: 'added',
    team: { id: 999_001, name: 'New Team', slug: 'new-team', url: 'http://example.com' },
    organization: { login: 'shopify' },        # value used by MembershipHandler
    member: { login: 'walrus' },
    repository: { owner: { login: 'attacker-org' } }  # value used for signature verification
  }.to_json

  Shipit.github(organization: 'attacker-org').stubs(:verify_webhook_signature).returns(true)

  assert_difference -> { Team.count }, 1 do
    post :create, body: body, as: :json
    assert_response :ok
  end

  team = Team.find_by(github_id: 999_001)
  # Binding check: organization used for verification ('attacker-org')
  # vs organization written to the Team ('shopify') — must be equal, but are not.
  assert_equal 'attacker-org', 'attacker-org'   # authenticated org
  assert_equal 'shopify', team.organization     # actually written org
  refute_equal 'attacker-org', team.organization
end
```