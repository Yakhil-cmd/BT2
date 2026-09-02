### Title
Cross-tenant `github_id` collision in `MembershipHandler#find_or_create_team!` allows attacker-controlled org to hijack Team membership authorization - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` derives `repository_owner` from `params.dig('organization', 'login')` when no `repository` key is present, and validates the webhook against `Shipit.github(organization: repository_owner)`'s secret [1](#0-0) [2](#0-1) . That correctly proves the request came from `attacker-org`'s real GitHub App/secret, but the `MembershipHandler` looks up the local `Team` record purely by `params.team.id` (`github_id`), never checking that the team's `organization` matches the org that actually authenticated the request [3](#0-2) .

### Finding Description
The broken binding: the code implicitly assumes `Team.find(github_id: params.team.id).organization == repository_owner (the org whose secret verified the signature)`. In reality `Team.find_or_create_by!(github_id: params.team.id)` only creates-with-org on first insert; on a match, it returns the existing row with its original `organization`/`github_id` regardless of which org's webhook secret verified this particular request.

Exploit flow: the attacker configures a legitimate tenant `attacker-org` in `Shipit.github_teams`-style config, with a genuine webhook secret. They send `POST /webhooks` with header `X-Github-Event: membership`, no `repository` key, and:
```json
{
  "action": "added",
  "team": { "id": <github_id of a Team belonging to some OTHER real org>, "name": "...", "slug": "...", "url": "..." },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-github-username" }
}
```
`repository_owner` falls back to `organization.login` = `'attacker-org'` [2](#0-1) . `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and checks the signature against attacker-org's own secret — which is genuinely valid since the attacker crafted and signed the request themselves [1](#0-0) . The request passes signature verification entirely legitimately. `MembershipHandler#process` then calls `find_or_create_team!`, which matches the pre-existing `Team` (belonging to a different, real org) purely by `github_id`, ignoring `params.organization.login` except in the creation-only block [3](#0-2) . `team.add_member(member)` then adds `User.find_or_create_by_login!(params.member.login)` — the attacker's own GitHub login — as a member of that Team [4](#0-3) .

If that Team's `id` is in `Shipit.github_teams`, `User#authorized?` becomes true for the attacker: `@authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [5](#0-4) . No existing guard prevents this: `verify_signature` only proves *an* org's secret matched, not that it's the *correct* org for the `github_id` in the payload; `drop_unhandled_event` and the `ExplicitParameters` schema in `MembershipHandler` only validate shape, not org/team ownership consistency.

### Impact Explanation
This is a cross-tenant authorization escalation into `Shipit.github_teams`: an attacker who legitimately controls one configured GitHub org/App secret can grant themselves membership in a `Team` record that actually corresponds to a *different* organization's real GitHub team, as long as they can guess or discover that team's numeric `github_id`. Once added, `User#authorized?` flips to true, granting the escalated privileges (e.g., deploy/rollback/merge authorization gated on team membership) that this other org's team confers, without any interaction from that org. This matches the High severity category ("escalation into `Shipit.github_teams` authorization"). It is repeatable for any `github_id` the attacker can enumerate, and its blast radius spans all tenants sharing the same Shipit instance's `github_teams` table.

### Likelihood Explanation
Preconditions: multi-tenant Shipit deployment where multiple orgs are configured via `Shipit.github(organization: ...)` (each with distinct webhook secrets), and at least one `Team` exists in `Shipit.github_teams` with a `github_id` the attacker can discover (team github IDs are not typically secret — visible via GitHub UI/API for public orgs, or leaked via other webhook traffic/logs). The attacker needs no more than a genuinely configured (even self-registered) GitHub org/App on the same Shipit instance and the target's numeric team `github_id`. This is a low-cost, fully repeatable attack requiring no compromise of any Shipit secret.

### Recommendation
In `find_or_create_team!`, verify that the found team's `organization` matches `params.organization.login` (the org actually verified by the webhook signature) before allowing `add_member`/`remove` operations; if it doesn't match, reject/log rather than silently operating on the mismatched record. More robustly, `verify_signature` should record which org verified the request and `MembershipHandler` should scope `Team.find_or_create_by!` on both `github_id` and `organization`, raising if an existing record's `organization` differs from the verified org.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/membership_handler_test.rb`):
1. Fixture setup: create `Team` `T1` with `github_id: 999`, `organization: 'real-org'` (a different, pre-existing tenant). Configure `Shipit.github_teams` to include `T1`.
2. Configure a second tenant `attacker-org` with its own valid webhook secret via `Shipit.github(organization: 'attacker-org')` test double/config.
3. Build a `membership` payload with **no** `repository` key, `organization.login = 'attacker-org'`, `team.id = 999` (T1's github_id, copied from the `real-org` fixture), `member.login = 'attacker-user'`, `action: 'added'`.
4. Sign the raw body with `attacker-org`'s legitimate secret and POST to `/webhooks` with `X-Github-Event: membership`.
5. Assert: response is `200 OK` (signature verified); `T1.reload.members.map(&:login)` includes `'attacker-user'`; `User.find_by(login: 'attacker-user').authorized?` is `true` — proving the binding `Team.find_by(github_id: 999).organization == 'attacker-org'` is false (it's `'real-org'`) yet the attacker gained membership and authorization anyway.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-28)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
