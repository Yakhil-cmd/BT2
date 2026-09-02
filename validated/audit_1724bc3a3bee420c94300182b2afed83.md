### Title
Cross-organization webhook can delete a legitimate `Membership` row via `MembershipHandler` `'removed'` action - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` derives the organization used to look up the webhook secret from the event payload's own `organization.login` field (there is no `repository` key on `membership` events), so any attacker who owns a GitHub organization configured in Shipit can sign an arbitrary `membership` payload with their own webhook secret. `MembershipHandler#process` then resolves the `Team` purely by `github_team.id` and mutates its `Membership` records without ever checking that the payload's `organization.login` matches the `Team#organization` that actually owns that `github_id`. This lets an attacker's own signed webhook delete a `Membership` belonging to a victim organization's team.

### Finding Description
The broken binding is:
`verified_org (Shipit.github(organization: repository_owner))` == `org_that_owns_the_mutated_Team (team.organization)`

This does not hold. In `app/controllers/shipit/webhooks_controller.rb`:
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 
For a `membership` event there is no `repository` key, so `repository_owner` is taken directly from the attacker-controlled `organization.login` field in the JSON body. `verify_signature` then does:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [2](#0-1) 
If the attacker owns/administers a GitHub organization that is itself onboarded into Shipit (has its own `webhook_secret` configured), they can sign the payload with their own secret and pass `verify_signature` — regardless of which organization's team is referenced inside the payload body.

Inside the handler:
```ruby
def process
  team = find_or_create_team!
  member = User.find_or_create_by_login!(params.member.login)
  case params.action
  when 'added'
    team.add_member(member)
  when 'removed'
    team.members.delete(member)
  ...
end

def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [3](#0-2) 
`find_or_create_by!(github_id: params.team.id)` looks the `Team` up solely by GitHub team ID. If a `Team` row already exists for the victim's real team (created earlier from the victim org's legitimate webhook), the block that sets `team.organization` is **not** re-executed on find — only on creation. The attacker only needs to know (or guess) the victim team's numeric GitHub `id` and the victim member's `login`; both are commonly discoverable via GitHub's public/team APIs or UI. `User.find_or_create_by_login!` resolves the member purely by login string, with no organization scoping either.

Exploit flow:
1. Attacker owns/administers a GitHub org "attacker-org" that is a configured Shipit organization (has a `webhook_secret`).
2. Attacker crafts a JSON body: `{"action":"removed","team":{"id":<victim_team_github_id>,"name":"...","slug":"...","url":"..."},"organization":{"login":"attacker-org"},"member":{"login":"<victim-user>"}}`.
3. Attacker signs it with `attacker-org`'s webhook secret and POSTs to `/webhooks` with `X-Github-Event: membership`.
4. `verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC matches (attacker's own secret) — signature check passes.
5. `MembershipHandler#process` finds the existing `Team` row by `github_id` (the victim's real team), resolves/creates the victim `User` by login, and executes `team.members.delete(member)`, deleting the `Membership` row that authorizes the victim user for `Shipit.github_teams`.

No other guard catches this: `drop_unhandled_event` only checks the event name is handled; the `ExplicitParameters` schema only validates types/presence, not cross-field consistency; there is no `Team#organization`-vs-`repository_owner` equality check anywhere in the handler or controller.

### Impact Explanation
The attacker can silently strip an operator's `Shipit.github_teams` authorization for a team belonging to an organization they do not control, by using signature material scoped to their own organization. This is a cross-tenant, unauthorized mutation of another organization's authorization state (a `Membership` row), matching "escalation/deauthorization impacting `Shipit.github_teams` authorization" and "cross-tenant mutation of another organization's ... team" — repeatable against any `Team#github_id` the attacker can discover, for as many victim users/teams as desired, at no cost beyond owning one Shipit-onboarded GitHub org.

### Likelihood Explanation
Preconditions: (1) the attacker must control at least one GitHub organization that is itself configured in Shipit with a `webhook_secret` (i.e., is a legitimate, if unrelated, tenant of the same Shipit instance) — this is a normal, low-cost setup step, not a privileged Shipit role; (2) the attacker must know the numeric GitHub `team.id` of the victim's target team and the victim's GitHub login, both of which are frequently obtainable through GitHub's team/member APIs or UI without special privileges. No Shipit session, API token, or GitHub secret belonging to the victim org is required. This is directly repeatable for any team whose `github_id` the attacker can enumerate.

### Recommendation
In `MembershipHandler#find_or_create_team!` (and in `WebhooksController#verify_signature` generally), require that the verified webhook-signing organization equals the `Team#organization`/`organization.login` in the payload before performing any mutation — reject (or re-verify) if `params.organization.login != repository_owner used for signature verification`, and additionally re-validate `team.organization == params.organization.login` for existing teams found by `github_id`, aborting the `'removed'`/`'added'` action if they diverge.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "membership 'removed' webhook signed by attacker org deletes victim org's membership" do
  victim_team = shipit_teams(:shipit)  # or create! organization: 'victim-org', github_id: 4242
  victim_user = shipit_users(:walrus)
  victim_team.add_member(victim_user)
  assert_difference -> { victim_team.memberships.count }, -1 do
    payload = {
      action: 'removed',
      team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
      organization: { login: 'attacker-org' }, # attacker-controlled org, NOT victim-org
      member: { login: victim_user.login }
    }.to_json
    signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', attacker_org_webhook_secret, payload)
    post shipit.github_webhooks_path,
      params: payload,
      headers: { 'X-Github-Event' => 'membership', 'X-Hub-Signature' => signature, 'Content-Type' => 'application/json' }
    assert_response :ok
  end
  refute victim_team.members.reload.include?(victim_user)
end
```
Assert on both sides of the binding: before the request, `victim_team.organization == 'victim-org'` while the signature is verified via `Shipit.github(organization: 'attacker-org')`; after the request, `Membership.exists?(team: victim_team, user: victim_user)` is `false`, proving the mutation occurred despite the org mismatch.

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
