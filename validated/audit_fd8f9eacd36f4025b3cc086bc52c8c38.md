## Title
Cross-tenant Team Membership mutation via unscoped `Team.find_or_create_by!(github_id:)` lookup - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` resolves a `Team` purely by the attacker-supplied numeric `params.team.id` (GitHub's team ID), without verifying that the team actually belongs to the organization (`params.organization.login`) that signed and sent the webhook. Because `User.find_or_create_by_login!` also resolves users globally (not scoped to the signing org), a webhook signed by one GitHub organization ("attacker-org") can add or remove membership rows on a `Team` belonging to an entirely different organization ("victimorg"), revoking or granting a real user's Shipit authorization without their org ever emitting the event.

### Finding Description
The broken binding: a `Membership` row mutated by a `membership` webhook must satisfy `team.organization == repository_owner` (the org whose secret verified the signature). Instead, the code only enforces `team.github_id == params.team.id`.

Path:
1. `Shipit::WebhooksController#verify_signature` computes `repository_owner` from the payload itself — for a `membership` event there is no `repository` key, so it falls back to `params.dig('organization', 'login')` [1](#0-0) . It then verifies the signature using `Shipit.github(organization: repository_owner).verify_webhook_signature` [2](#0-1) . If `organization.login` in the JSON body is set to "attacker-org", the signature only needs to match attacker-org's own configured webhook secret — a secret the attacker legitimately controls for their own org's integration.
2. `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` [3](#0-2) . This lookup is keyed solely on the attacker-controlled `github_id` integer; if it collides with an existing `Team` row (e.g. `shopify_developers`) that belongs to `victimorg`, that row is returned unchanged — the `organization` mismatch is never checked.
3. `User.find_or_create_by_login!(params.member.login)` resolves users globally by login (no org scoping), so it matches the real, existing victim employee's `User` record.
4. In the `'removed'` branch, `team.members.delete(member)` [4](#0-3)  deletes the `Membership` row joining the victim's team and the victim's user — a mutation on `victimorg`'s data, driven entirely by a payload signed by `attacker-org`.

No code path re-validates `team.organization` against `params.organization.login` or `repository_owner` after the initial `find_or_create_by!`, so the mismatch silently passes.

### Impact Explanation
An attacker who controls (or has legitimately configured) their own GitHub org integrated with the same Shipit instance can send a single crafted `membership` webhook that deletes (or, in the `'added'` case, adds) a `Membership` for any `Team` whose `github_id` they know or can guess, regardless of which org that team actually belongs to. This directly revokes a legitimate user's `Shipit.github_teams` authorization (or grants an attacker-chosen login access to a victim org's team) without any action by the victim org. This matches the Critical category: "a payload for one repository mutating another's ... team," and also constitutes escalation/de-escalation into `Shipit.github_teams` authorization.

### Likelihood Explanation
Preconditions: (a) the Shipit instance is multi-tenant, i.e. more than one GitHub organization is configured under `Shipit.github_teams`/per-org `GitHubApp` config, and the attacker legitimately controls one such org's webhook secret for their own, unrelated org; (b) the attacker knows or can guess the victim team's numeric GitHub team ID (not secret — discoverable via GitHub API/UI) and the victim user's GitHub login (public). Given those, the attack is a single unauthenticated-looking HTTP POST to `/webhooks` with a valid signature computed from the attacker's own known secret — fully repeatable against any team ID, for either `'added'` or `'removed'` actions.

### Recommendation
In `find_or_create_team!`, verify that any existing `Team` matched by `github_id` has `team.organization == params.organization.login` (and that this equals the `repository_owner` used to verify the signature) before returning it; raise/reject on mismatch rather than silently reusing the record. Consider scoping the `Team.find_or_create_by!` query on `github_id` **and** `organization` together, and rejecting the webhook if `params.organization.login` does not match the org used for signature verification.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/membership_handler_test.rb` style, or controller-level in `test/controllers/webhooks_controller_test.rb`):
1. Set up two org configs in `Shipit.github_teams`/app config: `shopify` (victim) and `attacker-org` (attacker), each with a distinct known `webhook_secret`.
2. Seed `shipit_teams(:shopify_developers)` with `organization: 'shopify'` and a known `github_id`, and add a `Membership` for an existing `shopify` user via `team.add_member(user)`.
3. Build a `membership` JSON payload with `action: 'removed'`, `organization.login: 'attacker-org'`, `team.id` equal to `shopify_developers.github_id`, `member.login` equal to the victim user's login.
4. Sign the raw payload with `attacker-org`'s webhook secret and POST to `/webhooks` with header `X-Github-Event: membership`.
5. Assert `Membership.count` for `shopify_developers` decreases by 1, i.e. `assert_difference -> { shipit_teams(:shopify_developers).members.count }, -1 do ... end`, proving `team.organization` ("shopify") was mutated by a payload whose verified signer was `"attacker-org"` — the two values (`team.organization` vs. the signing org) differ, confirming the binding violation.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L29-30)
```ruby
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
