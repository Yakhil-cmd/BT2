### Title
Cross-organization Team hijack via `Team.find_or_create_by!(github_id:)` in `MembershipHandler#process` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` only proves that a request body was HMAC-signed with the `webhook_secret` belonging to the organization named in `params.dig('organization','login')` (or `repository.owner.login`); it does not verify that any other field inside that same, attacker-authored JSON body (such as `team.id`) truly belongs to that organization. `MembershipHandler#find_or_create_team!` then looks up/creates a `Team` solely by `github_id: params.team.id`, and when a record with that id already exists it silently returns the existing row without touching `organization`, so a signed-but-forged payload from a legitimate but different org can attach/remove `Membership` rows on a `Team` owned by a completely different organization.

### Finding Description
The broken binding is: `webhook_secret_owner(organization.login in signed body) == team.organization (owner of Team row keyed by github_id)`. In practice, only the first is checked at the controller layer.

Path:
1. `Shipit::WebhooksController#create` (app/controllers/shipit/webhooks_controller.rb:10-15) parses `request.raw_post` and dispatches to handlers after `verify_signature` (line 6) has run.
2. `verify_signature` (lines 24-30) computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` (lines 59-62) is read directly from the attacker-controlled payload (`organization.login`), then calls `github_app.verify_webhook_signature(signature, request.raw_post)`, which is `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb:76-83) — a pure HMAC-SHA1 check over the *entire raw body* using the secret configured for that named organization. If the attacker legitimately administers `attacker-org` in Shipit (precondition given), they know its `webhook_secret`, so they can sign **any** JSON body they want, including one containing `"team": {"id": N, ...}` where `N` is the `github_id` of `shipit_teams(:shopify_developers)` or any other org's `Team` row, and `"organization": {"login": "attacker-org"}`.
3. `MembershipHandler#process` (app/models/shipit/webhooks/handlers/membership_handler.rb:22-34) calls `find_or_create_team!` (lines 38-43):
   ```ruby
   Team.find_or_create_by!(github_id: params.team.id) do |team|
     team.github_team = params.team
     team.organization = params.organization.login
   end
   ```
   `ActiveRecord::Relation#find_or_create_by!` runs the block **only when creating a new record**. If a `Team` with `github_id: N` already exists (the victim's `shopify` team), the existing record is returned unmodified — `organization` is never reassigned or checked against `params.organization.login`.
4. Back in `process`, `member = User.find_or_create_by_login!(params.member.login)` creates/looks up a `User` for an attacker-supplied login, and `team.add_member(member)` (app/models/shipit/team.rb:41-43) inserts a `Membership` row linking that user to the victim's `Team`.

No other guard intervenes: `ExplicitParameters` (the `params do ... end` schema) only validates types/presence, not cross-field authenticity; there is no comparison anywhere between the webhook's authenticated organization and the `organization` column of the `Team` being mutated.

### Impact Explanation
An attacker who legitimately controls one org onboarded into Shipit (with its own valid `webhook_secret`) can add or remove `Membership` rows on any `Team` record whose `github_id` they can predict or enumerate (team ids are visible via GitHub's API/UI and are not secrets), including teams belonging to unrelated, more privileged organizations such as `shopify`. Because `Shipit.github_teams` / `Team` membership is used by Shipit for authorization decisions (e.g., who can deploy/administer stacks tied to that org), this is a direct escalation into `Shipit.github_teams` authorization for a victim org, without ever possessing the victim's secret. This matches the "High: escalation into `Shipit.github_teams` authorization" impact category. The attack is repeatable (add/remove membership repeatedly, for any user login of the attacker's choosing) and crosses tenant boundaries in a multi-org Shipit deployment.

### Likelihood Explanation
Preconditions: (a) Shipit is configured with more than one organization's GitHub App/webhook_secret (multi-tenant deployment) and the attacker legitimately controls one of them; (b) the attacker can learn or guess a target `Team`'s `github_id` (GitHub team ids are enumerable/visible, not secret). Given that, the attack costs nothing beyond crafting one signed HTTP POST to `/webhooks` with a `X-Github-Event: membership` header — no GitHub interaction, no privileged Shipit access, no secrets belonging to the victim org are needed. This is fully feasible from the described unprivileged-attacker capability set.

### Recommendation
In `find_or_create_team!`, verify that any existing `Team` matched by `github_id` actually belongs to `params.organization.login` before reusing it (e.g., `Team.find_by(github_id: ...)` and raise/reject if `team.organization != params.organization.login`, or scope the lookup by both `github_id` and `organization`). More generally, `MembershipHandler` should treat `params.organization.login` as untrusted unless cross-checked against the org that `verify_signature` already resolved (`repository_owner`)/the webhook_secret owner, and reject mismatches instead of trusting the JSON body's `organization` field for anything beyond that initial signature check.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/webhooks/membership_handler_test.rb`):
1. Configure two orgs in test secrets: `shopify` (owning `shipit_teams(:shopify_developers)`, fixture `github_id: N`) and `attacker-org`, each with distinct `webhook_secret`s.
2. Build a membership webhook payload: `{"action":"added","team":{"id": N, "name":"x","slug":"x","url":"http://x"},"organization":{"login":"attacker-org"},"member":{"login":"attacker_login"}}`.
3. Sign the raw JSON with `attacker-org`'s `webhook_secret` (HMAC-SHA1), set `X-Hub-Signature` and `X-Github-Event: membership`, POST to `/webhooks`.
4. Assert response is `:ok`.
5. Before-state: `shipit_teams(:shopify_developers).members.map(&:login)` does not include `"attacker_login"`; `shipit_teams(:shopify_developers).organization == "shopify"`.
6. After-state (post-request): assert `shipit_teams(:shopify_developers).reload.members.map(&:login).include?("attacker_login")` is `true`, and `shipit_teams(:shopify_developers).organization` is still `"shopify"` (unchanged) — proving a request authenticated only by `attacker-org`'s secret mutated a `shopify`-owned `Team`'s membership.