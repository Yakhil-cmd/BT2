### Title
Cross-organization team-membership forgery via unscoped `Team.find_or_create_by!(github_id:)` lookup - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` resolves the target `Team` solely by the attacker-controlled `params.team.id`, with no check that the webhook's verifying organization (`params.organization.login`, which is also the value `WebhooksController#verify_signature` uses to select the HMAC secret) matches the `organization` actually stored on that `Team` record. An attacker who controls a GitHub organization ("OrgA") registered in Shipit can send a validly-signed `membership` event naming an existing "OrgB" team's `github_id` and remove an arbitrary "OrgB" member.

### Finding Description
The broken binding: `verifying_organization (params.organization.login, used by Shipit.github(organization: repository_owner) in WebhooksController#verify_signature)` must equal `team.organization (the organization that actually owns the Team/membership being mutated)`.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` as `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and picks the HMAC secret via `Shipit.github(organization: repository_owner)` [2](#0-1) . For `membership` events there is no `repository` key, so `repository_owner` is exactly `params.organization.login` — a value fully controlled by whoever crafts the JSON body.
- `MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.github_team = params.team; team.organization = params.organization.login }` [3](#0-2) . The block that sets `team.organization` only runs on **creation**; if a `Team` row with that `github_id` already exists (created earlier by a legitimate "OrgB" webhook), `find_or_create_by!` simply returns the existing record, regardless of what `params.organization.login` says in the current request.
- `process` then executes `team.members.delete(member)` for `action == 'removed'` [4](#0-3) , mutating the real "OrgB" team's membership using a `member.login` that is also fully attacker-controlled.

Root cause: the `Team` lookup key (`github_id`) is decoupled from the field used for signature-organization selection (`params.organization.login`); nothing re-validates `team.organization == params.organization.login` on the found (non-created) path. `verify_signature` only proves the attacker knows the secret for whatever organization they *declare* in the same payload — it does not (and cannot, by construction) prove that the other IDs embedded in that payload (`team.id`, `member.login`) actually belong to that declared organization.

Attacker's exact request: attacker registers/controls "OrgA" in Shipit (has that org's webhook secret from their own legitimate configuration), then POSTs to `/webhooks` with header `X-Github-Event: membership`, body:
```json
{"action":"removed","team":{"id":<OrgB_team_github_id>,"name":"...","slug":"...","url":"..."},"organization":{"login":"OrgA"},"member":{"login":"<orgb-victim-login>"}}
```
signed with OrgA's `webhook_secret`. `verify_signature` succeeds (secret matches OrgA, and `organization.login` in the payload is self-consistently "OrgA"), but `find_or_create_team!` finds the pre-existing "OrgB" `Team` row by `github_id` and the handler removes the named user from it.

### Impact Explanation
This lets an attacker who only controls their own GitHub organization ("OrgA") wired into Shipit remove members from a `Team` belonging to an unrelated organization ("OrgB"), including teams listed in `Shipit.github_teams` that gate deploy authorization via `User#authorized?`. This is a cross-tenant integrity violation and directly matches the "escalation into `Shipit.github_teams` authorization" High-severity category (de-authorizing a legitimate deployer is an availability/authorization impact on another tenant). It is repeatable against any `Team` whose `github_id` the attacker can learn or guess, and requires no privileges beyond controlling one org's webhook secret in a multi-org Shipit deployment.

### Likelihood Explanation
Requires: (1) Shipit configured with more than one GitHub organization/app entry (multi-tenant setup, common per `docs/setup.md`), (2) the attacker controlling/administering at least one such organization ("OrgA") so they legitimately know its `webhook_secret`, (3) a pre-existing `Team` row for the victim org ("OrgB") with a `github_id` the attacker can discover (team IDs are often discoverable via GitHub's API/UI). Given those, the attack is a single crafted HTTP POST with a correctly computed HMAC — no GitHub-side interaction and no additional secrets needed, so it is cheap and fully repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization` (e.g., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and additionally verify on every event that an existing team's stored `organization` equals `params.organization.login` before allowing any membership mutation, raising/dropping the event otherwise.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/membership_handler_test.rb`):
1. Seed `Team.create!(github_id: 999, organization: 'OrgB', slug: 'deployers', name: 'Deployers', api_url: 'https://api.github.com/teams/999')` and add `member = User.find_or_create_by_login!('orgb-victim')` via `team.add_member(member)`.
2. Assert precondition: `assert_includes team.members, member`.
3. Configure `Shipit.github(organization: 'OrgA')` with a known `webhook_secret` (as in existing `secrets.test.json`/dummy config).
4. Build payload `{"action" => "removed", "team" => {"id" => 999, "name" => "Deployers", "slug" => "deployers", "url" => "https://api.github.com/teams/999"}, "organization" => {"login" => "OrgA"}, "member" => {"login" => "orgb-victim"}}.to_json`, sign it with OrgA's `webhook_secret` (`sha1=` + HMAC), set `X-Github-Event: membership` and `X-Hub-Signature`.
5. POST to `/webhooks`; assert `response.status == 200`.
6. Reload `team`; assert `refute_includes team.reload.members, member` — proving the "OrgB" team's membership was mutated by a request that only proved knowledge of "OrgA"'s secret, confirming `verifying_organization == team.organization` does not hold.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L26-30)
```ruby
          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
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
