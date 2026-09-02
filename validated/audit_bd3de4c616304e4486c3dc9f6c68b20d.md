### Title
Cross-tenant `Team` membership write via unscoped `github_id` lookup in `MembershipHandler#find_or_create_team!` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` resolves a `Team` record purely by `params.team.id` (`github_id`) with no scoping to `params.organization.login`, so a membership webhook signed by *any* configured tenant organization's `webhook_secret` can add members to a `Team` row that was created by, and legitimately belongs to, a different configured organization if the two organizations' GitHub team ids happen to collide. Because Shipit supports multi-tenant deployments (multiple GitHub orgs each with their own `webhook_secret`, as shown in `test/dummy/config/secrets_double_github_app.yml`), a tenant that owns one configured org can forge a valid signature over an arbitrary `team.id` and get `Team.find_or_create_by!(github_id:)` in [1](#0-0)  to match a pre-existing `Team` belonging to another tenant, then call `team.add_member(member)`.

### Finding Description
Broken binding: the code assumes `github_id` uniqueness implies "same team, same org" (`Team.find_or_create_by!(github_id: params.team.id)` == "the team that legitimately belongs to `params.organization.login`"), but nothing in `find_or_create_team!` checks `team.organization == params.organization.login` on the found (non-created) path [1](#0-0) . The `organization.login` value is only used inside the `create!` block, i.e. only the first time a `Team` with that `github_id` is created; on every subsequent lookup that finds an existing row, the organization field of the found record is never re-validated against the incoming payload.

`process` then unconditionally calls `team.add_member(member)` for `action == 'added'`, appending a `Membership` between the (possibly wrong-tenant) `Team` and the freshly created/looked-up `User` [2](#0-1) , and `Team#add_member` performs no organization check either [3](#0-2) .

Signature verification in `WebhooksController#verify_signature` only proves that the payload was signed with the `webhook_secret` belonging to `repository_owner`/`organization.login` as resolved by `Shipit.github(organization: repository_owner)` [4](#0-3) . It proves authenticity of "this event came from org X's app", not that the `team.id` embedded in the payload actually belongs to org X — GitHub team ids are namespaced per organization in reality, but Shipit's model never enforces that binding.

Exploit flow: an attacker who legitimately administers Org B (a second tenant configured in Shipit's `github:` secrets, each org having its own `webhook_secret`, e.g. `OrgOne`/`OrgTwo` pattern) can sign an arbitrary `membership` `added` event with `team.id` set to a value they know or guess (small sequential GitHub ids), `organization.login: "OrgB"`, and any `member.login`. If that `team.id` collides with a `Team` row already created from Org A's real membership hooks, `find_or_create_by!` returns Org A's row, and the attacker's chosen member is added to it — writing a `Membership` for a team the attacker's org never controls.

### Impact Explanation
The result is an authorization-record write for a foreign tenant: a `Membership` linking an attacker-controlled `User` to a `Team` that legitimately belongs to another organization, without ever validating against GitHub that this user is really a member of that team. If Shipit's `Shipit.github_teams`/oauth-team-restricted access model treats `Team`/`Membership` rows as the source of truth for authorization (as implied by `oauth.teams` restricting access, per `docs/setup.md`), this could escalate an unprivileged outsider into a team whose membership grants access, matching the High-severity category "escalation into `Shipit.github_teams` authorization." The blast radius is limited to `Team`/`Membership` rows and requires no repository-level trust; it is repeatable for any `github_id` the attacker can guess.

### Likelihood Explanation
This requires the Shipit deployment to be genuinely multi-tenant, i.e. configured with more than one GitHub organization each holding its own `webhook_secret` in `config/secrets.yml` (this configuration shape is directly supported and documented, e.g. `test/dummy/config/secrets_double_github_app.yml`). The attacker must control (own/administer) one of those configured organizations so its `webhook_secret`-signed webhooks are accepted — they do not need any Shipit credentials, session, or the victim org's secret. Given that GitHub team ids are small monotonically increasing integers, guessing a collision with a victim's already-synced `Team.github_id` is plausible with limited attempts. For single-tenant deployments (the common case, one org's secrets only) this path is not exploitable, since only that one org's signature verifies at all. This constrains likelihood to multi-tenant Shipit installations specifically.

### Recommendation
Scope the `Team` lookup by both `github_id` and `organization` (e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and additionally guard `process` to reject/raise when an existing `Team` found by `github_id` has an `organization` that does not match `params.organization.login`, rather than silently reusing the row for `add_member`/`members.delete`.

### Proof of Concept
minitest plan (webhooks controller, no live GitHub):
1. Create fixture `Team` with `organization: 'victim'`, `github_id: 555`, `slug: 'core'`.
2. Stub `GithubHook`/`Shipit.github(organization: 'attacker')` (or via existing double-org secrets fixture) so `verify_webhook_signature` returns true for org `attacker`'s payload (mirrors `GithubHook.any_instance.stubs(:verify_signature).returns(true)` pattern already used in `test/controllers/webhooks_controller_test.rb`).
3. POST `membership` event: `X-Github-Event: membership`, body `{ action: 'added', team: { id: 555, name: 'Evil', slug: 'evil', url: '...' }, organization: { login: 'attacker' }, member: { login: 'mallory' } }`.
4. Assert: before request, `Team.find_by(github_id: 555).organization == 'victim'` and `Team.find_by(github_id: 555).members` does not include user `mallory`.
5. After request (`assert_response :ok`), assert `Team.find_by(github_id: 555).organization` is still `'victim'` (unchanged) AND `Team.find_by(github_id: 555).members.exists?(login: 'mallory')` is `true` — demonstrating a `Membership` was written into the victim's `Team` as a result of an `attacker`-signed webhook, breaking the equality `team.organization == params.organization.login`.

### Citations

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

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
