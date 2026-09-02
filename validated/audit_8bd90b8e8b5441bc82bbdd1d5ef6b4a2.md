### Title
Membership webhook team lookup by global `github_id` lets an org with no `webhook_secret` add members to another org's `Team` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` authenticates a webhook against the organization named in `params['organization']['login']` (or `repository.owner.login`), but `Shipit::Webhooks::Handlers::MembershipHandler#find_or_create_team!` looks up the target `Team` solely by `github_id`, with no check that the team's `organization` matches the organization whose signature was verified. If two GitHub orgs are configured in the multi-tenant `secrets.github` map and one has a blank `webhook_secret`, an attacker who can trigger/craft a `membership` webhook against that weakly-configured org can mutate a `Team` record belonging to a different, already-existing organization.

### Finding Description
The broken binding is: `organization whose signature verified the request bytes` (`repository_owner` in `app/controllers/shipit/webhooks_controller.rb:59-62`, resolved to `params.dig('organization','login')`) must equal `organization owning the Team record being mutated`. It does not.

- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) returns `true` unconditionally when `webhook_secret` is blank for that organization's config.
- `MembershipHandler#process` then calls `find_or_create_team!` (`app/models/shipit/webhooks/handlers/membership_handler.rb:38-42`):
  ```ruby
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
  ```
  This looks up `Team` **only by `github_id`**, which is attacker-supplied and can be set to match a real `Team` row created previously for a victim org (e.g. `shipit_teams(:shopify_developers)` with `github_id: 1`, `organization: shopify`, per `test/fixtures/shipit/teams.yml:3-9`). Because the record already exists, `find_or_create_by!`'s block (which sets `organization`) never runs, and the code proceeds to operate on the victim's real `Team` object.
- `team.add_member(member)` (`app/models/shipit/team.rb:41-43`) then appends `User.find_or_create_by_login!(params.member.login)` — the attacker's own GitHub login — to that victim team's `members`.

Attacker request: `POST /webhooks` with header `X-Github-Event: membership`, body:
```json
{
  "action": "added",
  "organization": { "login": "attacker-org-with-blank-secret" },
  "team": { "id": <victim_team_github_id>, "name": "...", "slug": "...", "url": "..." },
  "member": { "login": "attacker-login" }
}
```
Because `attacker-org-with-blank-secret` has no `webhook_secret` configured, `verify_signature` passes trivially. Nothing in `drop_unhandled_event`, `ExplicitParameters` schema (`MembershipHandler.params`, `app/models/shipit/webhooks/handlers/membership_handler.rb:7-21`), or `Team.find_or_create_by!` cross-checks that `params.organization.login` matches the `organization` column already stored on the found `Team`.

### Impact Explanation
The attacker becomes a member of an arbitrary victim `Team` record (`Shipit::Team`) identified only by knowing/guessing its GitHub team `id`. Since `Shipit.github_teams` (`lib/shipit.rb:256-258`) resolves configured OAuth team handles to `Team` rows, and `User#authorized?` (`app/models/shipit/user.rb:80-82`) grants application access to any user whose `teams` intersect `Shipit.github_teams` by `id`, this is a path to escalate into `Shipit.github_teams` authorization for a team the attacker does not actually belong to on GitHub — matching the High severity category ("escalation into `Shipit.github_teams` authorization"). The blast radius crosses tenant boundaries: a webhook authenticated for org A mutates a `Team` belonging to org B.

### Likelihood Explanation
This requires: (1) a multi-org Shipit deployment (`secrets.github` keyed by multiple organizations, as in `test/dummy/config/secrets_double_github_app.yml`), (2) at least one configured organization with a blank `webhook_secret`, and (3) a pre-existing `Team` row for a different, privileged org (naturally created by legitimate prior webhooks or `Team.find_or_create_by_handle`). Given those preconditions — which are plausible in real multi-org configurations where one org's webhook secret was never set — the attack is cheap (a single unauthenticated HTTP POST) and fully repeatable against any known `github_id`.

### Recommendation
Scope the `Team` lookup in `find_or_create_team!` by both `github_id` and `organization` (matching `params.organization.login`), e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and/or have `verify_signature`/the handler reject the event if an existing `Team` for that `github_id` has a different `organization` than the one that authenticated the request.

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb` (multi-org test setup with two `Shipit.github` configs, one with blank `webhook_secret`):
```ruby
test ":membership from an org with no webhook secret can add a member to another org's team" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: 1
  request.headers['X-Github-Event'] = 'membership'
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    stub(verify_webhook_signature: true) # blank webhook_secret => true
  )
  payload = {
    action: 'added',
    organization: { login: 'attacker-org' },
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    member: { login: 'attacker' },
    repository: { owner: { login: 'attacker-org' } }
  }.to_json

  assert_difference -> { victim_team.reload.members.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end
  assert_includes victim_team.members.map(&:login), 'attacker'
end
```
This asserts the equality break directly: the organization that authenticated the webhook (`attacker-org`) differs from `victim_team.organization` (`shopify`), yet `User.find_by(login: 'attacker')` becomes a member of `victim_team`.