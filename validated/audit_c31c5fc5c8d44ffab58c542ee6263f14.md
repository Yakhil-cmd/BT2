### Title
Cross-tenant team membership forgery via missing organization-ownership check in `MembershipHandler#process` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` only proves that a request was signed with the secret of whichever `GithubHook::Organization` matches `params.dig('organization','login')` (attacker-controlled JSON, not the signature key itself). `MembershipHandler#process` then looks up the `Team` purely by `params.team.id` (GitHub's numeric team id) and calls `team.add_member(member)` without ever checking that the org that produced a valid signature is the same org that owns that `Team` row (`team.organization`, set once at creation). Any tenant that has validly onboarded its own org can therefore mutate the membership of a `Team` belonging to a different tenant's org, as long as it knows/guesses the victim team's numeric `github_id`.

### Finding Description
The binding that should hold is: `verified_signature_organization == team.organization` for the `Team` being mutated. In reality the code only enforces `verified_signature_organization == params.dig('organization','login')` (i.e., the signature is checked against whatever org login string is embedded in the JSON body, which the attacker fully controls), and never checks that value against the persisted `team.organization`.

Path:
1. `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)`. For a `membership` event there is normally no `repository` key, so this resolves to the attacker-supplied `organization.login`.
2. If the attacker administers org **B** (their own onboarded org with its own `GithubHook::Organization` secret), they can craft an arbitrary raw JSON body, put `"organization": {"login": "orgB"}` in it, and sign it with orgB's real webhook secret (which they legitimately possess, since they configured Shipit for orgB themselves). `verify_signature` passes.
3. `MembershipHandler#process` (app/models/shipit/webhooks/handlers/membership_handler.rb:22-43) does:
```ruby
team = find_or_create_team!
member = User.find_or_create_by_login!(params.member.login)
case params.action
when 'added'
  team.add_member(member)
```
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
```
`find_or_create_by!` looks the `Team` up **only by `github_id` (params.team.id)**. If a `Team` with that `github_id` already exists (created earlier, legitimately, under victim org **A**), the block is skipped — `team.organization` remains `"orgA"` — but the record returned is still used for `team.add_member(member)`. There is no comparison anywhere between `params.organization.login` (which was what authorized the request, "orgB") and the existing `team.organization` ("orgA").
4. `Team#add_member` (app/models/shipit/team.rb:41-43) unconditionally appends the member: `members.append(member) unless members.include?(member)`.

Thus an attacker who (a) legitimately administers org B with its own valid Shipit `GithubHook::Organization` webhook secret and (b) knows/guesses the numeric GitHub `team.id` of a team belonging to org A, can add (or, symmetrically, remove) arbitrary users from org A's `Team`/`Membership` records by forging a `membership` webhook signed with org B's own secret. Existing guards (`verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema in `MembershipHandler.params`) only validate signature and JSON shape — none of them tie the authenticated org to the specific `Team` row being mutated.

### Impact Explanation
This allows one tenant's validly-configured GitHub organization webhook to mutate `Shipit::Team`/`Shipit::Membership` records that belong to a different tenant's organization on the same Shipit instance — a direct cross-tenant authorization bypass matching the "payload for one repository/org mutating another's team" Critical category. If `Shipit.github_teams`/team membership feeds into authorization elsewhere in the app (e.g., `User#authorized?`/`require_permission!` checks against `Shipit::Team` membership), this also becomes a path to escalate into `Shipit.github_teams` privileges by adding an attacker-controlled `member.login` to a privileged team, or to purge legitimate members via the `removed` action — repeatable against any team `github_id` the attacker can enumerate, across arbitrarily many onboarded tenants.

### Likelihood Explanation
Preconditions: the attacker must legitimately control at least one org onboarded to the same shared Shipit instance with a configured `GithubHook::Organization` (this is explicitly listed as an allowed attacker capability in the prompt: "attacker administers two distinct orgs onboarded to the same Shipit instance"). The attacker needs the victim `Team`'s numeric GitHub `github_id`, which for many orgs is discoverable (GitHub team IDs are low-entropy sequential integers, and team pages/APIs can leak them for teams the attacker can view, or the attacker could have observed them from prior legitimate webhook traffic to Shipit if logs are shared, or simply brute-force small integers). No Shipit session, API token, or GitHub App secret theft is required — only knowledge of a secret the attacker already legitimately owns. This is low-cost and fully repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!`/`#process`, after resolving the `Team`, verify that the webhook's authenticated organization matches the team's `organization` column before performing any mutation, e.g. raise/drop the event (or return 422/404 without mutating) if `team.organization != params.organization.login`. Additionally, `find_or_create_by!` should scope the lookup by `(github_id:, organization: params.organization.login)` rather than `github_id` alone, so a colliding/guessed `github_id` from a different org cannot resolve to a foreign `Team` row at all.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (proof sketch)
test "membership event from org B cannot mutate a team owned by org A" do
  org_a_team = shipit_teams(:shopify_developers) # created/owned by organization "shopify"
  assert_equal 'shopify', org_a_team.organization

  # Attacker's own org "orgb" has a valid GithubHook::Organization fixture/secret
  GithubHook::Organization.create!(organization: 'orgb', event: 'membership', secret: 'orgb-secret')

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: org_a_team.github_id, name: org_a_team.name, slug: org_a_team.slug, url: org_a_team.api_url },
    organization: { login: 'orgb' },      # attacker's own org, signs with its own secret
    member: { login: 'attacker-controlled-user' }
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', 'orgb-secret', payload)}"
  @request.headers['X-Hub-Signature'] = signature

  assert_no_difference -> { Membership.where(team_id: org_a_team.id).count } do
    post :create, body: payload, as: :json
    assert_response :ok # currently succeeds and mutates org A's team -- should be rejected
  end
end
```
Both sides of the binding to assert: `verified_organization` ("orgb") must equal `org_a_team.organization` ("shopify") before any membership write; today the code never checks this and the write succeeds.