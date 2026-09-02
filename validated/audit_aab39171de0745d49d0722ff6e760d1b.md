### Title
Membership webhook signature-authenticates `repository.owner.login` while `MembershipHandler` writes `Team`/`Membership` rows for the independently-attacker-controlled `organization.login` - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a webhook against the organization derived from `params.dig('repository','owner','login')`, falling back to `params.dig('organization','login')` only when `repository` is absent. `MembershipHandler#find_or_create_team!` and `#process`, however, always use `params.organization.login` to create/update `Team` rows and to add/remove `Membership` rows, without ever consulting `repository_owner`. Because the `membership` event's `ExplicitParameters` schema only requires `action`, `team`, `organization`, `member` (no `repository`), an attacker can inject an arbitrary extra `repository` object into the JSON body to steer signature verification to an organization whose secret they know, while `organization.login` (the value actually used to mutate `Team`/`Membership`) points at a different, victim organization tracked in `Shipit.github_teams`.

### Finding Description
Binding claimed to hold: `authenticated_org (WebhooksController#repository_owner)` == `org_whose_rows_are_mutated (MembershipHandler params.organization.login)`.

- `repository_owner` [1](#0-0)  resolves to `params.dig('repository','owner','login')` first, falling back to `params.dig('organization','login')` only if `repository` is missing.
- `verify_signature` calls `Shipit.github(organization: repository_owner)` and validates the HMAC signature against that organization's configured `webhook_secret` [2](#0-1) .
- `MembershipHandler` schema requires only `action`, `team`, `organization`, `member` — `repository` is not part of the schema and is not validated or rejected if present [3](#0-2) .
- `find_or_create_team!` creates/updates a `Team` with `team.organization = params.organization.login`, and `process` adds/removes the member on that team [4](#0-3) . This path never calls `Handler#stacks`/`#repository_name`, so it is not gated by `repository_name` at all — it only trusts `params.organization.login`.

For a real GitHub `membership` event, the payload has no `repository` key, so `repository_owner` normally falls back to `organization.login`, and the two values naturally coincide. An attacker who administers/owns an organization configured in Shipit (knows its `webhook_secret`) can craft a raw JSON POST to `/webhooks` with `X-Github-Event: membership` where:
- `repository.owner.login` = attacker's own org (used only to select the signing secret),
- `organization.login` = victim org already present in `Shipit.github_teams`,
- `member.login` = an account the attacker controls,
- `action` = `"added"`.

Signing the raw body with the attacker's own org's `webhook_secret` passes `verify_signature` (it authenticates the attacker's org), yet `MembershipHandler` creates/updates a `Team` scoped to the victim org and adds the attacker's account as a member of that team — writing authorization-relevant rows for an organization whose secret the attacker never possessed.

No existing guard stops this: `drop_unhandled_event` only checks that a handler exists for the event name, not payload consistency; the `ExplicitParameters` schema for `MembershipHandler` does not require or cross-check `repository`; `force_github_authentication`/`User#authorized?`/`require_permission!` are not invoked in this webhook path.

### Impact Explanation
A successful request causes a `Team` record (and via `team.add_member`, a `Membership` record) to be created/mutated for an organization the attacker does not control, using only the credentials of a different organization the attacker does control. Since `Shipit.github_teams`-based authorization presumably relies on `Team`/`Membership` records to grant stack/deploy permissions, this is a direct escalation into another tenant's authorization scope — matching the "High: escalation into `Shipit.github_teams` authorization" (and arguably higher, since it plants attacker-controlled membership) impact category. The attack is repeatable against any victim organization login the attacker chooses to place in `organization.login`, for every `membership` webhook the attacker sends, as long as the attacker owns/administers at least one org configured with its own `webhook_secret` in Shipit.

### Likelihood Explanation
Preconditions: Shipit must be a multi-tenant deployment with multiple organizations each configured with their own `webhook_secret` (typical of the `Shipit.github_teams` multi-org setup), and the attacker must legitimately administer at least one such organization (so they know that organization's own webhook secret). No Shipit session, API token, or GitHub secret belonging to the victim org is required. Crafting and sending the forged payload is a single unauthenticated HTTP POST to `/webhooks` with a valid HMAC computed from the attacker's own known secret — trivial and fully repeatable.

### Recommendation
In `MembershipHandler` (and any other handler that trusts an organization identifier from the payload independently of the identifier used for signature verification), require that the mutated organization match the organization that was cryptographically authenticated. Concretely: pass `repository_owner` (or the authenticated organization) from `WebhooksController` into the handler, and have `MembershipHandler#find_or_create_team!` verify `params.organization.login == authenticated_organization` before writing/mutating any `Team`/`Membership` row, rejecting (422) on mismatch. Also consider making `verify_signature`'s `repository_owner` resolution prefer the field(s) actually relevant to the specific event type rather than always preferring `repository.owner.login`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`-style, no live GitHub):
1. Configure two orgs in `Shipit.github_teams`/secrets fixtures: `attacker-org` (with `webhook_secret: 'attacker-secret'`) and `victim-org` (with its own distinct `webhook_secret`), mirroring existing dummy secrets setup.
2. Build payload:
```ruby
payload = {
  action: 'added',
  team: { id: 999, name: 'evil-team', slug: 'evil-team', url: 'https://api.github.com/teams/999' },
  organization: { login: 'victim-org' },
  member: { login: 'attacker-user' },
  repository: { owner: { login: 'attacker-org' } }
}.to_json
signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', payload)
```
3. POST to `/webhooks` with header `X-Github-Event: membership` and `X-Hub-Signature: signature`.
4. Assert response is `200 OK` (signature accepted for `attacker-org`, i.e. `repository_owner == 'attacker-org'`).
5. Assert `Shipit::Team.find_by(github_id: 999).organization == 'victim-org'` (mutation binding target), demonstrating `authenticated_org ('attacker-org') != mutated_org ('victim-org')`.
6. Assert `Shipit::Team.find_by(github_id: 999).members.exists?(login: 'attacker-user')` — the attacker is now a member of a team scoped to an org they never authenticated as.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
```ruby
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
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
