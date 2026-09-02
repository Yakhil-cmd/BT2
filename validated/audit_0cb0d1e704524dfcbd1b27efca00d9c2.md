### Title
`Team.find_or_create_by_handle` matches on organization+slug, letting a pre-created forged Team row hijack the configured `Shipit.github_teams` slot - ([File: app/models/shipit/team.rb])

### Summary
`Shipit.github_teams` (memoized once per process) resolves each configured handle via `Team.find_or_create_by_handle`, which looks the row up by `organization`+`slug` only, never by `github_id`. If a `Team` row for that exact organization/slug already exists — e.g. created ahead of time by the `membership` webhook handler, which trusts attacker-supplied `github_id`/`slug`/`organization` fields — the memoized lookup silently reuses that row instead of creating a fresh, GitHub-verified one, so any `Membership` already attached to it (also attacker-created via the same webhook) becomes a valid authorization path.

### Finding Description
Binding claimed: `Shipit.github_teams.map(&:id)` == ids of `Team` rows genuinely fetched from GitHub for the configured handles (`lib/shipit.rb:256-258`, `app/models/shipit/team.rb:18-21`).

Trace:
- `Shipit.github_teams` memoizes `github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }` once per process (`lib/shipit.rb:256-258`).
- `Team.find_or_create_by_handle(handle)` does `find_by(organization:, slug:) || fetch_and_create_from_github(...)` — the lookup key is `organization`+`slug` (which also carries the DB unique index `index_teams_on_organization_and_slug`), never `github_id` (`app/models/shipit/team.rb:18-21`).
- `MembershipHandler#find_or_create_team!` creates/finds a `Team` keyed on the webhook payload's `github_id`, and assigns `organization`/`slug`/`name`/`api_url` directly from attacker-controllable payload fields with no cross-check against real GitHub data (`app/models/shipit/webhooks/handlers/membership_handler.rb:38-43`, `app/models/shipit/team.rb:53-58`). It also creates/looks up the `member` purely from `params.member.login` and calls `team.add_member(member)` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-33`).
- This handler is reachable through `POST /webhooks` for the `membership` event, gated only by `WebhooksController#verify_signature`, which calls `GitHubApp#verify_webhook_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`). Critically, `verify_webhook_signature` is `return true unless webhook_secret` (`lib/shipit/github_app.rb:76-83`) — i.e. if the operator's org config has no `webhook_secret` set (documented as "optional" in `docs/setup.md`), every unsigned POST is accepted with no attacker secret required at all.

Exploit flow (only feasible when `webhook_secret` is unset for the target org, and before any code in the process has yet called `Shipit.github_teams`, e.g. right after a deploy/worker restart):
1. Attacker POSTs a forged `membership` webhook with `organization.login` = the real configured org (public), `team.slug`/`team.organization` = the real configured team's slug (must be guessed/known), a made-up `team.id`, and `member.login` = the attacker's own real GitHub login.
2. `MembershipHandler` creates a `Team` row with the real org/slug but a bogus `github_id`, and creates a `Membership` linking the attacker's `User` row to it.
3. The first time `Shipit.github_teams` is computed in that process, `find_by(organization:, slug:)` finds the attacker's pre-existing row (same org/slug) and returns it — it is never re-verified against GitHub, and the DB unique index on `organization`+`slug` would in fact prevent creating a second, legitimate row for the same handle.
4. The attacker's row's id is now part of `Shipit.github_teams.map(&:id)`. When the attacker logs in normally via GitHub OAuth, `User#authorized?` (`app/models/shipit/user.rb:80-82`) finds their pre-existing `Membership` and grants access.

Existing guards do not stop this: `verify_signature` only blocks the request if a `webhook_secret` is actually configured for that org; nothing in `MembershipHandler` or `Team.find_or_create_by_handle` cross-checks `github_id` or re-fetches the team from GitHub once a same-organization/slug row exists.

### Impact Explanation
An attacker who can reach an org with no `webhook_secret` configured can self-grant membership in whatever `Team` row ultimately occupies the configured `organization/slug` handle, causing `User#authorized?` to return true and bypassing Shipit's team-based access control entirely — full unauthorized access to the application (stacks, deploys, secrets used in tasks) for that installation. This matches the "escalation into `Shipit.github_teams` authorization" High-severity category (and can enable further Critical actions such as unauthorized deploys once inside). It is repeatable each time the target process's `Shipit.github_teams` memo is reset (deploys/restarts), not a one-shot bug.

### Likelihood Explanation
Exploitability is entirely gated on the org's `webhook_secret` being unset — a documented, permitted (if not recommended) configuration in `docs/setup.md`. If a `webhook_secret` is configured (the norm for production), `verify_signature` blocks the forged webhook outright and this path is fully closed. The attacker also needs to know the exact `organization/slug` of the configured team, and win a race against the process's first, memoized call to `Shipit.github_teams` after a deploy/restart — a narrow but recurring window. Given these preconditions, likelihood is moderate-to-low but non-theoretical for any installation that leaves `webhook_secret` blank.

### Recommendation
- Require `webhook_secret` to be configured for every org that has a `membership` (or any) webhook registered, and refuse to boot/accept webhooks for orgs missing it instead of defaulting to `verified = true`.
- Have `Team.find_or_create_by_handle` validate/refresh against `github_id` fetched live from GitHub (or re-verify `fetch_and_create_from_github` data) rather than trusting a pre-existing `organization`+`slug` row unconditionally, or reconcile handler-created rows against `Shipit.github_teams`' authoritative GitHub-sourced `github_id` before trusting existing `Membership` rows.

### Proof of Concept
In `test/models/team_test.rb` / `test/unit/shipit_test.rb` style:
```ruby
test "a webhook-created Team row hijacks the configured Shipit.github_teams slot" do
  Shipit.stubs(:github_teams).returns(nil) # reset memoization for isolation, or clear @github_teams ivar
  Shipit.instance_variable_set(:@github_teams, nil)
  Shipit.github.stubs(:oauth_teams).returns(['shopify/developers'])

  # 1. Attacker forges membership webhook (simulate webhook_secret unset -> verify_webhook_signature stubbed true)
  attacker = users(:mallory)
  forged_team = Shipit::Webhooks::Handlers::MembershipHandler.new.tap do |h|
    # process with payload: organization.login=shopify, team.slug=developers, team.id=999999, member.login=mallory
  end
  # -> creates Team(organization: 'shopify', slug: 'developers', github_id: 999999)
  # -> creates Membership(team: that Team, user: attacker)

  # 2. Legitimate first-access computation of Shipit.github_teams
  real_team_ids_before = Shipit::Team.where(organization: 'shopify', slug: 'developers').pluck(:id)
  computed_ids = Shipit.github_teams.map(&:id)

  # Binding check: computed_ids should equal ids of GitHub-verified teams only
  assert_not_includes computed_ids, forged_team_id_from_step_1  # FAILS: attacker's id is included
  refute attacker.authorized? # FAILS: attacker.authorized? is actually true, proving bypass
end
```
This demonstrates that `Shipit.github_teams.map(&:id)` includes the attacker's forged row id and that `User#authorized?` returns true for a user who was never a real GitHub team member.