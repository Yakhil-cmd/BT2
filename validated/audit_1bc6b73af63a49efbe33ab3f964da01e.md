### Title
Cross-organization team membership write via `Team.find_or_create_by!(github_id:)` in `MembershipHandler#find_or_create_team!` - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` looks up a `Team` solely by `github_id`, ignoring the `organization` field in the same verified payload. An attacker who controls a Shipit-registered GitHub organization (with its own valid, independently-configured webhook secret) can send a `membership` webhook whose `team.id` collides with an existing `Team` row belonging to a different, more privileged organization, causing their own GitHub user to be added as a member of that foreign team.

### Finding Description
The broken binding is: `team.organization == params.organization.login` must hold for any `Team` row mutated by a webhook whose signature was verified for that same `organization.login`. In `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` [1](#0-0) , the block that sets `organization` (and other github_team fields) only executes when the row is newly created. If a `Team` with that `github_id` already exists (from a legitimate different organization), `find_or_create_by!` returns the existing row unmodified — `team.organization` remains the original org's login, not the attacker's.

The controller-level guard, `WebhooksController#verify_signature`, resolves the GitHub App/secret to check against based on `repository_owner`/`organization.login` taken directly from the attacker-controlled payload [2](#0-1) . This only proves the payload was legitimately sent by the organization named in it — it does not bind the `team.id` inside the payload to that organization. So an attacker who administers their own registered GitHub organization (with Shipit's app installed and a webhook secret configured, per the multi-org setup documented in `docs/setup.md`) can produce a validly-signed `membership` "added" webhook for their organization, but set `team.id` to a numeric value that happens to match (or is engineered to match, since GitHub team IDs are globally unique but attacker can observe/guess or brute force smaller ranges) the `github_id` of a privileged team already stored for a different org.

Back in `process`, since `action == 'added'`, `team.add_member(member)` is called on the fetched (foreign) `Team` object, appending the attacker's own `User` (created via `User.find_or_create_by_login!(params.member.login)`) to that team's `members` [3](#0-2)  and [4](#0-3) . Nothing in `ExplicitParameters` schema, `drop_unhandled_event`, or `verify_signature` cross-checks that the team resolved by `github_id` actually belongs to the organization asserted in the payload.

### Impact Explanation
If the colliding `Team.github_id` corresponds to a team referenced in `Shipit.github_teams` (used for authorization, e.g. granting operator/maintainer privileges), the attacker gains membership in that team as recorded by Shipit, which can escalate their `User#teams`/`User#authorized?` results and unlock privileged actions gated on team membership — this is a cross-tenant authorization write reachable with a single unauthenticated (from Shipit's perspective, only GitHub-signed) webhook POST, repeatable against any team whose `github_id` the attacker can determine or guess.

### Likelihood Explanation
Requires: (1) Shipit configured for multiple organizations (each with its own webhook secret) per `docs/setup.md`'s "Using Multiple Github Applications" section, and the attacker controlling one of them; (2) knowledge or guessing of a target `github_id` already present in the `teams` table. This is plausible in shared/multi-tenant Shipit deployments serving multiple orgs, which is an explicitly supported configuration. Attacker cost is low — one crafted, validly-signed webhook per attempt.

### Recommendation
In `find_or_create_team!`, scope the lookup by both `github_id` and `organization`, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and reject/raise if a `Team` with that `github_id` exists under a different organization rather than silently reusing it.

### Proof of Concept
minitest plan (e.g. in `test/controllers/webhooks_controller_test.rb` style, using two distinct configured orgs like `test/dummy/config/secrets_double_github_app.yml`):
1. Seed `Team.create!(github_id: 48, organization: 'OrgOne', slug: 'privileged-team', name: 'Privileged', api_url: '...')`.
2. Post a `membership` webhook, signed for `OrgTwo`, with `organization: { login: 'OrgTwo' }`, `team: { id: 48, name: 'Fake', slug: 'fake', url: '...' }`, `member: { login: 'attacker' }`, `action: 'added'`.
3. Assert `team.reload.organization == 'OrgOne'` (unchanged) yet `team.members.map(&:login)` now includes `'attacker'`, proving a member from `OrgTwo`'s verified webhook was written into `OrgOne`'s team — i.e. `team.organization` (`'OrgOne'`) != `params.organization.login` (`'OrgTwo'`) while the write still succeeded.

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
