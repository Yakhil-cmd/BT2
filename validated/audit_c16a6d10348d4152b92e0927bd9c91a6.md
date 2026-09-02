### Title
Cross-tenant Team hijack via membership webhook `github_id`-only lookup - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a webhook only against the `webhook_secret` of the organization named in the payload's `organization.login` field, while `MembershipHandler#find_or_create_team!` resolves the target `Team` purely by the numeric `team.id` (GitHub team ID), never checking that the team belongs to the authenticating organization. An attacker who legitimately administers their own tenant organization can sign a `membership` webhook with their own valid `webhook_secret` but reference the `github_id` of a team belonging to a different, unrelated organization already listed in `Shipit.github_teams`, causing themselves to be added as a `Membership` of that team.

### Finding Description
The broken binding is: `organization_that_signed_the_request` (`params.organization.login`, used in `Shipit.github(organization: repository_owner)` at `app/controllers/shipit/webhooks_controller.rb:25,61`) should equal `organization_owning_the_mutated_Team_row` (`Team#organization` of the row matched by `github_id`), but nothing enforces this.

Path:
1. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` from `params.dig('organization','login')` since a `membership` event has no `repository` key (`app/controllers/shipit/webhooks_controller.rb:59-62`). It resolves `Shipit.github(organization: 'attacker-org')` and verifies the signature against attacker-org's own `webhook_secret`. This succeeds because the attacker legitimately controls `attacker-org`, a configured tenant.
2. `MembershipHandler#process` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`) calls `find_or_create_team!`.
3. `find_or_create_team!` (`app/models/shipit/webhooks/handlers/membership_handler.rb:38-43`) does `Team.find_or_create_by!(github_id: params.team.id)`. Since a `Team` row for `shopify` already exists with that `github_id` (a precondition of the scenario), this is a *find*, not a *create* — the `organization.login` value from the (attacker-signed) payload is never compared to the existing team's `organization` column.
4. `team.add_member(member)` is invoked on the found shopify `Team`, inserting a `Membership` linking `attacker-login`'s `User` to that team.
5. `User#authorized?` (`app/models/shipit/user.rb:80-82`) checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?`. If the hijacked team is in `Shipit.github_teams`, the attacker's `User` now passes this check.

None of the existing guards catch this: `verify_signature` authenticates the *organization identity*, not the *team's ownership*; there is no `ExplicitParameters` cross-field constraint tying `team.id` to `organization.login`; and `Team` has no validation binding `github_id` to `organization`.

### Impact Explanation
A single crafted, self-signed webhook grants the attacker a `Membership` row in a team they were never actually added to on GitHub, and if that team is enumerated in `Shipit.github_teams`, `User#authorized?` returns `true` for the attacker — a full authentication/authorization bypass into Shipit for a multi-tenant install, without ever needing shopify's (or any victim organization's) `webhook_secret`. This is repeatable against any known/guessable GitHub team `github_id` and requires only that the attacker control one legitimately configured tenant organization in the same Shipit instance. This matches the "Critical – authentication bypass (forged webhook ... accepted)" / "escalation into `Shipit.github_teams` authorization" categories.

### Likelihood Explanation
Preconditions: multi-tenant Shipit configuration (multiple organizations each with their own `webhook_secret` in secrets), attacker legitimately administers one such tenant org, a target `Team` row already exists (created via a prior legitimate GitHub team webhook or `lib/tasks/teams.rake`) for a different organization and is listed in `Shipit.github_teams`, and the attacker can learn/guess that team's numeric GitHub `github_id` (discoverable via GitHub's public/team APIs in many cases, or by observing prior webhook traffic). Attacker cost is low: crafting and signing one HTTP POST with their own secret. This is a realistic, low-cost, fully attacker-controlled action requiring no privileged Shipit or GitHub secrets belonging to the victim.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup/creation by both `github_id` and `organization` (e.g., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and additionally validate/reject if an existing `Team` with that `github_id` belongs to a different `organization` than the authenticating one (raise/drop the event rather than silently reusing the row). More generally, `WebhooksController#verify_signature` should ensure the authenticated organization matches every organization-scoped resource mutated by the handler, not just the top-level `repository_owner`.

### Proof of Concept
Minitest integration test outline (under `test/controllers/webhooks_controller_test.rb`, not to be created here but described):
1. Configure two organizations in test secrets: `shopify` (secret `S1`) and `attacker-org` (secret `S2`).
2. Create `victim_team = Shipit::Team.create!(github_id: 4242, organization: 'shopify', handle: 'shopify/some-team')` and stub `Shipit.github_teams` to include it.
3. Build a `membership` webhook payload: `{action: 'added', team: {id: 4242, name: 'some-team', slug: 'some-team', url: '...'}, organization: {login: 'attacker-org'}, member: {login: 'attacker-login'}}`.
4. Sign the raw JSON body with `S2` (attacker-org's own secret) and POST to `/webhooks` with header `X-Github-Event: membership`.
5. Assert response is `200 OK` (signature accepted).
6. Assert: `Shipit::User.find_by(login: 'attacker-login').teams.pluck(:id)` includes `victim_team.id` — i.e., `Shipit::Membership.exists?(team: victim_team, user: attacker_user)`.
7. Assert `Shipit::User.find_by(login: 'attacker-login').authorized?` returns `true`, demonstrating the equality `organization_that_signed('attacker-org') != organization_owning_team('shopify')` was violated and exploited.