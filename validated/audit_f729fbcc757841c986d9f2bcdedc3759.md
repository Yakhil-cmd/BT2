### Title
`MembershipHandler#find_or_create_team!` skips reassigning `Team#organization` on existing teams, letting unrelated orgs write memberships to it - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` only executes the block—and thus only sets/validates `organization`—on the very first insert of a `github_id`. For any subsequent webhook referencing an existing `github_id`, `find_or_create_by!` returns the already-persisted record untouched, so `team.organization` is never re-checked against `params.organization.login` before `team.add_member(member)`/`team.members.delete(member)` runs.

### Finding Description
Binding claimed: `Team#organization == params.organization.login` for the team object the handler subsequently mutates. Before the call the DB has `Team(github_id: 99, organization: 'shopify')`. `MembershipHandler#process` calls `find_or_create_team!`, which is `Team.find_or_create_by!(github_id: params.team.id) { |team| ...; team.organization = params.organization.login }` (`app/models/shipit/webhooks/handlers/membership_handler.rb:38-43`). Because `github_id: 99` already exists, ActiveRecord's `find_or_create_by!` finds the record and returns it directly without yielding the block, so `organization` stays `'shopify'` even though the verified payload's `organization.login` is `'attacker-org'`. `process` then unconditionally calls `team.add_member(member)` on this returned team (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-33`), inserting a `Membership` row for a team that belongs to `shopify`, using only the attacker's own org's authenticity.

Why signature verification does not stop this: `WebhooksController#verify_signature` derives the signing organization from `repository_owner`, which falls back to `params.dig('organization','login')` when there is no `repository` key (`app/controllers/shipit/webhooks_controller.rb:59-62`). GitHub's `membership` event payload contains no `repository` object, only `organization`. So the controller verifies the payload against `Shipit.github(organization: 'attacker-org')`'s webhook secret — which the attacker legitimately knows because it is *their own* org's registered webhook secret. The signature check is satisfied for `attacker-org`, not for `shopify`; there is no code anywhere that cross-checks that the `team.id` referenced actually belongs to the organization that signed the request. `require_permission!`, `User#authorized?`, and other authorization gates are irrelevant here because webhooks bypass session/API-token auth entirely and rely solely on signature-to-org binding, which this handler defeats by trusting the caller-supplied `team.id` against a different org's signed payload.

Attacker request: attacker registers/owns `attacker-org` as a Shipit-configured organization (with its own valid `webhook_secret`), then POSTs to `/webhooks` with header `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with `attacker-org`'s webhook secret, and body:
```json
{"action":"added","team":{"id":99,"name":"x","slug":"x","url":"http://x"},"organization":{"login":"attacker-org"},"member":{"login":"attacker"}}
```
Because `github_id: 99` already exists (belongs to `shopify_developers`), the create block is skipped, `team.organization` remains `'shopify'`, and `team.add_member` inserts a `Membership` associating the attacker's controlled GitHub user with `shopify`'s team.

### Impact Explanation
This is a cross-tenant authorization bypass: a party who only controls `attacker-org`'s webhook secret can insert themselves (or any GitHub login) into an arbitrary pre-existing `Team` belonging to a different, unrelated organization, merely by guessing/enumerating small integer `github_id` values. Team membership in Shipit typically underlies review/merge or deploy authorization checks tied to `Shipit.github_teams`/team membership, so this can escalate an attacker into privileges gated on membership of a `shopify`-owned team without ever being invited by `shopify`. This is repeatable against any `github_id` and any organization pair configured on the instance, so blast radius spans all tenants sharing the Shipit host. This matches the "escalation into `Shipit.github_teams` authorization" / cross-tenant mutation category (High/Critical depending on how team membership is consumed downstream).

### Likelihood Explanation
Preconditions: the Shipit instance must host multiple GitHub organizations (multi-tenant configuration, each with its own `webhook_secret` in `Shipit.github_hooks`/secrets config), and a `Team` row for some `github_id` must already exist for the victim org (created via a legitimate prior GitHub `membership` webhook or admin action). The attacker only needs to control one org among those configured (their own, with a webhook installed, giving them a valid signing secret) and to know or guess the numeric `github_id` of the victim team (team IDs are visible via GitHub's public API for teams whose org visibility permits it, or via prior events). No Shipit session, API token, or GitHub App private key is required — this uses only the attacker's legitimately-issued webhook secret for their own org. Cost is minimal: one crafted HTTP POST, repeatable at will.

### Recommendation
In `find_or_create_team!`, always verify/update `organization` outside the creation block and reject/reset if it does not match the currently verified webhook organization, e.g.:
```ruby
def find_or_create_team!
  team = Team.find_or_initialize_by(github_id: params.team.id)
  raise ArgumentError, "Team #{team.github_id} does not belong to #{params.organization.login}" if team.persisted? && team.organization != params.organization.login
  team.github_team = params.team
  team.organization = params.organization.login
  team.save!
  team
end
```
Additionally, `WebhooksController#verify_signature` should not blindly trust the payload's `organization.login` as the signing identity for events lacking a `repository` key without cross-validating it against the team/record actually being mutated.

### Proof of Concept
```ruby
test ":membership webhook cannot hijack a team belonging to another organization" do
  team = shipit_teams(:shopify_developers)
  original_org = team.organization
  assert_equal 'shopify', original_org

  @request.headers['X-Github-Event'] = 'membership'
  GithubApp.any_instance.stubs(:verify_webhook_signature).returns(true) # simulate valid signature for attacker-org

  assert_no_difference -> { Membership.count } do
    post :create, body: {
      action: 'added',
      team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
      organization: { login: 'attacker-org' },
      member: { login: 'attacker' }
    }.to_json, as: :json
  end

  team.reload
  assert_equal original_org, team.organization # binding must hold: organization unchanged by an unrelated org's payload
end
```
Currently this test fails: `Membership.count` increases by 1 and `team.organization` remains `'shopify'` while the membership add still succeeds, proving the unauthorized cross-tenant write.