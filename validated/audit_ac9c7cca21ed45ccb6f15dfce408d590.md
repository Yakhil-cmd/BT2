### Title
Cross-organization Team/Membership mutation via unscoped `github_id` lookup in `membership` webhook - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` resolves the target `Team` solely by the GitHub `team.id` in the webhook payload, never checking that the payload's `organization.login` (the value used by `WebhooksController#verify_signature` to pick which org's secret authenticated the request) actually matches the `organization` column already stored on that `Team`. Any tenant organization onboarded into this Shipit instance (i.e., one with its own valid, configured webhook secret) can therefore sign a `membership` `removed` event under its own name while pointing `team.id` at a different organization's already-existing `Team` row, deleting an arbitrary victim `Membership`.

### Finding Description
The binding the question implicitly assumes is:
`verify_signature succeeds for organization O` == `the mutated Team belongs to organization O`.

Tracing the code shows this is false:

- `WebhooksController#verify_signature` derives `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
  For `membership` events GitHub does not send a `repository` key, so this resolves to `params.organization.login` — this is exactly the organization whose configured secret must sign the payload, and nothing more.

- `MembershipHandler#find_or_create_team!` then looks the team up **only** by `github_id`, ignoring `organization` entirely on the "find" branch (the block that sets `team.organization` only runs when the record is newly created): [3](#0-2) 

- `process` then resolves the member globally by login (`User.find_or_create_by_login!`, keyed on `login` with no org scoping) and, for `action == 'removed'`, calls `team.members.delete(member)`: [4](#0-3) [5](#0-4) 

Exploit flow: an attacker who controls organization `attacker-org` — itself a legitimately onboarded Shipit tenant with its own configured webhook secret (not the victim's secret, not any Shipit/GitHub App secret) — sends `POST /webhooks` with header `X-Github-Event: membership`, a valid HMAC signature computed with `attacker-org`'s own secret, and a JSON body:
```
{
  "action": "removed",
  "organization": { "login": "attacker-org" },
  "team": { "id": <victim_team.github_id>, "name": "...", "slug": "...", "url": "..." },
  "member": { "login": "<victim-maintainer-login>" }
}
```
`verify_signature` passes because the signature genuinely matches `attacker-org`'s secret. `find_or_create_team!` finds the pre-existing `Team` row for `victim_team.github_id` (created earlier by the victim's legitimate GitHub webhooks) and returns it unchanged — its `organization` remains `"victim-org"`. `team.members.delete(member)` then deletes the `Membership` row linking the victim maintainer to the victim's team, stripping that maintainer's authorization derived via `User#authorized?` (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`) without any verified relationship between `attacker-org` and the victim's team. [6](#0-5) 

No existing guard prevents this: `verify_signature` only authenticates "who signed", not "which team is referenced"; the `ExplicitParameters` schema on `MembershipHandler` only validates types/presence, not organization ownership of the team ID; and `Team.find_or_create_by!(github_id:)` never re-checks or updates `organization` on the find path.

### Impact Explanation
A malicious or compromised tenant organization can mutate another organization's `Team`/`Membership` state — deleting (or, symmetrically, adding via `action: 'added'`) memberships it has no relationship to — purely by guessing/enumerating the victim's numeric GitHub team ID (visible via GitHub's public API/UI) and a maintainer's GitHub login (public). This directly strips a legitimate maintainer's Shipit authorization (`User#authorized?`) for the victim's stacks, which matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any team ID already known to Shipit's database and is not limited to a single victim organization.

### Likelihood Explanation
The attacker must control an organization that is itself a legitimately configured Shipit tenant (i.e., possesses a valid webhook secret registered in this Shipit instance for its own org) — this is a moderate precondition in any multi-tenant Shipit deployment where multiple GitHub orgs point their webhooks at the same shared Shipit host, but does not require access to the victim's secrets, GitHub App keys, or `secret_key_base`. Given that, the attacker only needs a publicly-discoverable numeric team ID and a maintainer login, both retrievable through unauthenticated GitHub UI/API browsing. The request is a single unauthenticated `POST /webhooks` call, trivially repeatable.

### Recommendation
In `find_or_create_team!`, scope the lookup by both `github_id` and `organization` (e.g., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and reject/raise if a `Team` with that `github_id` exists under a different `organization` than the one that authenticated the webhook. Additionally, have `WebhooksController#verify_signature` (or the handler) explicitly compare the authenticated `repository_owner`/`organization.login` against the resolved model's `organization` for every event type that references cross-referenced records by numeric GitHub ID.

### Proof of Concept
Minitest plan (extends `test/controllers/webhooks_controller_test.rb`):
```ruby
test ":membership cannot delete a membership belonging to a different organization" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify'
  victim_membership = shipit_memberships(:walrus_shopify_developers) # existing fixture linking 'walrus' to victim_team

  @request.headers['X-Github-Event'] = 'membership'
  GithubApp.any_instance.stubs(:verify_webhook_signature).returns(true) # simulate valid signature from attacker-org's own secret

  forged_payload = {
    action: 'removed',
    organization: { login: 'attacker-org' },
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    member: { login: 'walrus' }
  }.to_json

  assert_no_difference -> { Membership.count } do
    post :create, body: forged_payload, as: :json
    assert_response :ok
  end
end
```
Binding assertions: before the request, `victim_membership.team.organization == 'shopify'` while the request is authenticated for `organization.login == 'attacker-org'` (two different values). After the fix, `Membership.count` must be unchanged (assert_no_difference) because the referenced team does not belong to the authenticated organization; on the current code, this assertion fails — `Membership.count` decreases by 1 — proving the cross-organization mutation.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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

**File:** app/models/shipit/user.rb (L22-28)
```ruby
    def self.find_or_create_by_login!(login)
      find_or_create_by!(login:) do |user|
        # Users are global, any app can be used
        # This will not work for users that only exist in an Enterprise install
        user.github_user = Shipit.github.api.user(login)
      end
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
