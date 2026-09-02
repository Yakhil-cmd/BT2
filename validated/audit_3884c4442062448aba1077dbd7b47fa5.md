### Title
Cross-organization team hijack via membership webhook — `Team.find_or_create_by!(github_id:)` never validates the reporting organization - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` looks up an existing `Team` solely by `github_id`, and never checks that the webhook's `organization.login` matches the `organization` already stored on that `Team` row. In a multi-tenant Shipit deployment (multiple GitHub orgs configured under `secrets.github`), an attacker who legitimately administers their own onboarded organization can forge a validly-signed `membership` webhook for their own org, but reference the numeric `github_id` of a team belonging to a *different* org that is present in `Shipit.github_teams`, adding an attacker-controlled login to that privileged `Team`.

### Finding Description
The broken binding is: `Team#organization == params['organization']['login']` for the `Team` row matched by `github_id`. This holds only at creation time and is never re-checked on subsequent webhooks.

- `WebhooksController#verify_signature` selects the HMAC secret via `Shipit.github(organization: repository_owner)` [1](#0-0)  where `repository_owner` is taken straight from the attacker-supplied `organization.login` field of the payload [2](#0-1) . This only proves the request came from *some* organization configured in Shipit — it says nothing about which `team.id` is being referenced inside the body.
- `MembershipHandler#find_or_create_team!` resolves the target `Team` by `github_id` alone: [3](#0-2) 
  The `team.organization = params.organization.login` assignment only executes inside the `find_or_create_by!` block, i.e. only when the row doesn't already exist. If a `Team` with that `github_id` already exists (created previously for a different, legitimate organization), the block is skipped entirely and the existing `organization` value is never verified against the webhook's claimed `organization.login`.
- `#process` then unconditionally adds the attacker-controlled member to that team: [4](#0-3) 
- `Shipit.github_teams` (the set of teams that confer authorization) is built from a single default organization's `oauth_teams` config [5](#0-4)  and `User#authorized?` grants access to anyone whose `teams` intersect `Shipit.github_teams` [6](#0-5) .

Exploit flow: attacker legitimately administers Org B, which is configured in Shipit alongside the target Org A (`secrets.github` multi-org schema, see `README.md`/`secrets.development.example.yml`). Attacker crafts a `membership` webhook body: `{"action":"added","team":{"id":<Org A privileged team's github_id>,...},"organization":{"login":"org_b"},"member":{"login":"attacker_login"},"repository":{"owner":{"login":"org_b"}}}` and signs it with Org B's own webhook secret (which they legitimately possess as Org B's admin). `verify_signature` passes because it only checks Org B's secret against Org B's identity. `find_or_create_team!` then finds the pre-existing Org A `Team` row purely via `github_id` and `team.add_member(attacker_login_user)` persists a `Membership`. No check anywhere compares `params.organization.login` to the team's actual `organization` on the found-not-created path.

None of the existing guards catch this: `verify_signature` validates *origin authenticity*, not *object ownership consistency*; the `ExplicitParameters` schema on `MembershipHandler` only enforces types/presence, not cross-field/organization consistency [7](#0-6) ; `User#authorized?` trusts the `Membership` table without re-verifying against GitHub [6](#0-5) .

### Impact Explanation
An attacker who genuinely controls one tenant organization in a multi-tenant Shipit install can grant an arbitrary GitHub login (one they control and can authenticate as via OAuth) membership in a `Team` belonging to a different, unrelated organization, as long as that team's numeric `github_id` is known. If that team is among `Shipit.github_teams`, the attacker's login becomes `authorized?` for the whole Shipit instance, enabling access to every team-gated controller/action (deploys, rollbacks, merges) across all stacks the instance manages — not just Org B's. This matches the "High: escalation into `Shipit.github_teams` authorization" category defined in the rules; because that authorization subsequently unlocks deploy/rollback controllers, the practical blast radius is severe, though the escalation step itself is a High, not Critical, per the taxonomy given.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured for multiple GitHub organizations (`secrets.github` multi-org schema) where the attacker legitimately administers one of them, and (2) knowledge of the target team's numeric `github_id` (obtainable via GitHub's team API for teams the attacker can observe, or leaked/guessed IDs). This is a real, low-cost, repeatable attack for any tenant admin in a shared Shipit instance — a single crafted HTTP POST to `/webhooks` per target team, no GitHub App keys or `secret_key_base` needed. In single-organization Shipit deployments this path does not apply since there is only one `organization` value possible.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify `params.organization.login.downcase == team.organization` for teams found via `github_id`, and raise/reject on mismatch (or scope the lookup by `[github_id, organization]` instead of `github_id` alone).

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`):
1. Fixture setup: create `shipit_teams(:org_a_privileged)` with `organization: 'org_a'`, `github_id: 999`, and include it in `Shipit.github_teams` (stub `Shipit.github_teams` to return `[org_a_privileged]`).
2. Configure Shipit with two orgs: `org_a` and `org_b`, each with its own `GithubHook::Organization` webhook secret; stub `Shipit.github(organization: 'org_b').verify_webhook_signature` to return `true` (simulating attacker's legitimately-known Org B secret) while leaving Org A's secret unrelated/unknown.
3. POST to `/webhooks` with `X-Github-Event: membership`, body: `{"action":"added","team":{"id":999,"name":"x","slug":"x","url":"http://x"},"organization":{"login":"org_b"},"member":{"login":"attacker"},"repository":{"owner":{"login":"org_b"}}}`.
4. Assert `Shipit::Membership.count` increments by 1, `Shipit::User.find_by(login: 'attacker').authorized?` becomes `true`, and `shipit_teams(:org_a_privileged).organization` remains `'org_a'` (proving the team's real organization identity was never re-validated against the webhook's `org_b` claim) — i.e., assert the equality `team.organization == params['organization']['login']` is `false` yet the membership was written anyway.

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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
