### Title
Cross-organization team hijack via `MembershipHandler` grants `Shipit.github_teams` authorization across tenants - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against the `organization`/`repository.owner.login` field taken from the *same* payload being verified, then dispatches the event to `MembershipHandler`. `MembershipHandler#find_or_create_team!` looks up (or creates) a `Team` keyed **only** by `params.team.id` (GitHub's numeric team id) and only assigns `team.organization` inside the `find_or_create_by!` creation block — it never re-validates that the payload's claimed organization matches the `organization` already stored on an existing `Team` row. Since `User#authorized?` and `Shipit::Authentication#force_github_authentication` gate application access purely on `teams.where(id: Shipit.github_teams.map(&:id))`, this handler can be used to add arbitrary GitHub logins to any pre-existing privileged `Team` record as long as the attacker can produce a validly-signed webhook for *some* organization configured in the same Shipit instance.

### Finding Description
Signature verification and business-logic authorization are bound to different keys of the same untrusted payload:

- `app/controllers/shipit/webhooks_controller.rb` (`verify_signature`) resolves the org used to fetch the webhook secret from `params.dig('repository','owner','login') || params.dig('organization','login')`, i.e., from the payload itself:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
This only proves the request was signed by *some* configured organization's app secret — it proves nothing about which `Team` record the payload is allowed to mutate.

- `app/models/shipit/webhooks/handlers/membership_handler.rb`:
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end

def process
  team = find_or_create_team!
  member = User.find_or_create_by_login!(params.member.login)
  case params.action
  when 'added'
    team.add_member(member)
  ...
```
`find_or_create_by!(github_id: ...)` matches an **existing** `Team` row purely by its GitHub numeric team id, regardless of which organization signed the current webhook. If a `Team` with that `github_id` already exists (e.g. a privileged team referenced in `Shipit.github_teams`, previously synced from `TargetOrg`), the block is skipped and the found team (still bound to `TargetOrg`) is used as-is. `team.add_member(member)` then persists `member` (any GitHub login the attacker names) into that team in Shipit's database — with zero re-check that the currently-authenticating organization (`OrgA`, whose secret validated the signature) actually owns that team.

This breaks the trust binding: **organization that authenticated (the org whose `webhook_secret` verified `X-Hub-Signature`) ≠ team/organization actually written (`TargetOrg`'s privileged `Team` row)**.

Downstream, `User#authorized?` (`app/models/shipit/user.rb:80-82`) and `Authentication#force_github_authentication` (`app/controllers/concerns/shipit/authentication.rb:20-34`) grant full application access solely based on `teams.where(id: Shipit.github_teams.map(&:id)).exists?`. There is no re-verification against GitHub of actual team membership at authorization time — the local `Team`/`Membership` rows built entirely from webhook data are authoritative.

### Impact Explanation
This is a High-impact escalation into `Shipit.github_teams` authorization, one of the explicitly enumerated High-severity outcomes: an attacker who can produce one legitimately signed webhook (as an admin of any organization/app installation configured in the same multi-tenant Shipit instance, i.e. `OrgA`) can silently insert their own GitHub login as a member of a completely different, privileged `TargetOrg` team, bypassing GitHub's real team membership and gaining the equivalent of a full Shipit login/authorization without ever being a real member of `Shipit.github_teams`.

### Likelihood Explanation
Likelihood is constrained but non-trivial in the realistic deployment model this engine targets: Shipit is commonly configured with several GitHub organizations sharing one instance (`config/secrets.development.shopify.yml` shows multiple orgs each with independent `webhook_secret`s), and GitHub numeric team ids are discoverable via the public GitHub API for any team the attacker can enumerate/observe (team ids are not secrets, unlike webhook secrets). The attacker needs to control a GitHub App installation on any one configured org (to produce a validly signed `membership` webhook) — this is exactly the kind of unprivileged-relative-to-target, privileged-relative-to-own-org attacker the rules target (an authenticated-but-wrong-org actor, not a Shipit session/API token holder).

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup/update by both `github_id` and the payload's `organization.login`, and reject (or no-op) the event if an existing `Team` with that `github_id` is bound to a different organization than the one that authenticated the current webhook request. Additionally, pass the verified organization from `WebhooksController` down into the handler dispatch so business logic can assert `params.organization.login == verified_organization` before mutating any `Team`/`Membership` records.

### Proof of Concept
1. Shipit instance is configured with two GitHub App installations: `OrgA` (attacker-administered, attacker knows `webhook_secret_A`) and `TargetOrg` (victim org whose team `TargetOrg/admins`, GitHub team id `999`, is listed in `Shipit.github_teams`, and already has a `Team` row with `github_id: 999`, `organization: "TargetOrg"`).
2. Attacker crafts a `membership` webhook body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "admins", "slug": "admins", "url": "https://api.github.com/..." },
  "organization": { "login": "OrgA" },
  "member": { "login": "attacker-gh-login" }
}
```
3. Attacker signs the raw body with `webhook_secret_A` (which they legitimately possess) and sets `X-Hub-Signature` and `X-Github-Event: membership`, then POSTs to `/webhooks`.
4. `verify_signature` resolves `repository_owner` → `"OrgA"` (from `organization.login`, since no `repository` key is present), fetches `OrgA`'s app, and the signature validates successfully.
5. `MembershipHandler#find_or_create_team!` runs `Team.find_or_create_by!(github_id: 999)`, finds the pre-existing `TargetOrg` team (block not executed since record exists), and `team.add_member(User.find_or_create_by_login!("attacker-gh-login"))` adds the attacker's GitHub user to `TargetOrg/admins` in Shipit's database.
6. Attacker logs in via OAuth as `attacker-gh-login`; `User#authorized?` now returns `true` because `teams.where(id: Shipit.github_teams.map(&:id)).exists?` matches the injected membership, granting full application access without ever being a member of the real `TargetOrg/admins` GitHub team.