This confirms the same cross-tenant issue applies identically to the `removed` action.

### Title
Cross-org webhook signature scoping lets an attacker forge a `membership` `removed` event to delete a victim's `Membership` from another org's team - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
The `MembershipHandler#process` method resolves the target `Team` solely by the payload's `team.id` (GitHub's global team ID) and looks up/creates the target `User` solely by `member.login`, with no check that `organization.login` in the payload matches the team's or member's actual GitHub organization. Since `WebhooksController#verify_signature` selects the HMAC secret via `Shipit.github(organization: repository_owner)`, and `repository_owner` for membership events is read directly from the attacker-controlled `organization.login` field, an attacker who owns any org onboarded to Shipit can sign a payload with their own valid `webhook_secret` while setting `team.id` to a victim's team `github_id` and `member.login` to a victim's login, causing `team.members.delete(member)` to remove a legitimate, cross-tenant `Membership` row.

### Finding Description
The broken binding: the code assumes `params.organization.login == ` the actual GitHub org that owns `params.team.id`, i.e. that a validly-signed webhook's `organization` claim corresponds to the `team.id`/`member.login` claims it carries. This is never checked.

Path: `WebhooksController#verify_signature` computes `repository_owner` as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and verifies the signature using `Shipit.github(organization: repository_owner).verify_webhook_signature` [2](#0-1) . For `membership` events there is no `repository` key, so `repository_owner` is exactly the attacker-controlled `organization.login` field, and the secret used to verify the HMAC is the attacker's own org's `webhook_secret` (which the attacker legitimately possesses for their own onboarded org).

`MembershipHandler#process` then does:
```ruby
team = find_or_create_team!            # Team.find_or_create_by!(github_id: params.team.id)
member = User.find_or_create_by_login!(params.member.login)
case params.action
when 'removed'
  team.members.delete(member)
``` [3](#0-2) 

`find_or_create_team!` keys `Team` purely by the global `github_id`, ignoring which org actually owns that team [4](#0-3) . `team.members.delete(member)` maps to `has_many :members, through: :memberships` [5](#0-4) , so this destroys the `Shipit::Membership` join row for that `(team_id, user_id)` pair.

Exploit flow: the attacker registers/owns "evil-org" as a Shipit-integrated GitHub org (so they hold a valid `webhook_secret` for it and can send correctly-HMAC-signed webhook deliveries). They send a `POST /webhooks` request with header `X-Github-Event: membership`, HMAC-signed with evil-org's secret, and payload:
```json
{
  "action": "removed",
  "team": { "id": <victim_team_github_id>, "name": "...", "slug": "...", "url": "..." },
  "organization": { "login": "evil-org" },
  "member": { "login": "<victim-login>" }
}
```
`verify_signature` passes because the signature matches evil-org's secret and `repository_owner` (= "evil-org") correctly resolves to evil-org's `GitHubApp` instance. `drop_unhandled_event` passes because `membership` is a handled event. The `ExplicitParameters` schema in `MembershipHandler` only validates types/presence, not organizational ownership. `MembershipHandler#process` finds the victim's `Team` by `github_id` and deletes the `Membership` for the named victim login, without ever checking that `victim_team_github_id` belongs to `evil-org`.

### Impact Explanation
This lets an attacker who controls any Shipit-onboarded org unilaterally delete `Shipit::Membership` rows belonging to a different org's team, silently revoking a legitimate user's authorization status if `Shipit.github_teams` includes that team — `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) . Repeating this for every member of a privileged team can lock out an entire organization's authorized users from Shipit, a cross-tenant integrity/availability impact on the authorization model, matching "escalation into `Shipit.github_teams` authorization" (High) — here manifesting as unauthorized de-escalation/lockout rather than escalation, but through the identical broken cross-tenant binding as the 'added' case. The attack is fully repeatable against arbitrary victim team `github_id`s and logins, requiring only knowledge of the victim's login and team `github_id`, both of which are typically discoverable via public GitHub API/UI.

### Likelihood Explanation
Precondition: attacker owns/controls any GitHub org already onboarded to this Shipit instance (has a valid `webhook_secret` configured for that org) — as stated in the prompt, this is granted. No Shipit session, API token, or GitHub App secret for the victim org is needed. The victim's team `github_id` and login are typically obtainable from public GitHub data. Cost is a single crafted HTTP POST with a correctly computed HMAC using the attacker's own secret.

### Recommendation
In `MembershipHandler#process` (and `find_or_create_team!`), validate that `params.organization.login` matches the `organization` already recorded on the `Team` being resolved (i.e., look up `Team.find_by(github_id: params.team.id, organization: params.organization.login)` rather than by `github_id` alone), and reject/ignore the event if an existing team's recorded organization doesn't match the payload's organization. More generally, `WebhooksController#verify_signature` should ensure the verified org's `GitHubApp` is also the authoritative source for any embedded team/org claims used by handlers, not just used to pick the HMAC key.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual, no live GitHub)
test "membership 'removed' event cannot delete a membership belonging to another org's team" do
  victim_team = shipit_teams(:shopify_developers) # belongs to org "shopify", github_id e.g. 1
  victim_user = shipit_users(:walrus)
  victim_team.add_member(victim_user)
  assert_difference '-> { victim_team.members.reload.count }', 0 do
    # signature computed with evil-org's own webhook_secret
    Shipit.stubs(:github).with(organization: 'evil-org').returns(evil_org_github_app)
    request.headers['X-Github-Event'] = 'membership'
    request.headers['X-Hub-Signature'] = evil_org_signature_for(payload)
    post :create, body: {
      action: 'removed',
      team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
      organization: { login: 'evil-org' },
      member: { login: victim_user.login }
    }.to_json, as: :json
  end
  assert_includes victim_team.members.reload, victim_user
end
```
Currently, `assert_difference('Membership.count', -1)` succeeds after this forged cross-org `removed` event — demonstrating the bug: the equality `params.organization.login == actual_owning_org(params.team.id)` is never checked before `team.members.delete(member)` executes.

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
