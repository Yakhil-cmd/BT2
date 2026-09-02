This confirms the impact path: `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [1](#0-0) , so any user with a `Membership` row in one of `Shipit.github_teams` becomes globally authorized in this Shipit instance.

### Title
Membership webhook `Team.find_or_create_by!(github_id:)` ignores `organization` binding, allowing cross-tenant team membership injection - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` looks up an existing `Team` solely by `github_id` and never verifies that the requesting organization (the one whose `webhook_secret` validated the signature) matches the `organization` column already stored on that `Team` row. In a multi-org Shipit deployment, an org admin who legitimately controls their own tenant's GitHub App/webhook secret can forge a `membership` event referencing another tenant's team `github_id`, adding an arbitrary user to that team and bypassing `Shipit.github_teams` authorization for the victim tenant.

### Finding Description
The broken binding is: `organization_that_signed_the_webhook == organization_owning_the_Team_row_mutated`. This is never checked.

Trace:
1. `WebhooksController#verify_signature` resolves `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [2](#0-1) . For a `membership` event, only `organization.login` exists in the payload, so the app config it authenticates against is entirely attacker-controlled (as long as it names a real, legitimately-onboarded org in the multi-org secrets config, e.g. `attacker-org`) [3](#0-2) .
2. Once the signature check passes (using `attacker-org`'s own webhook secret, which its admin legitimately possesses), `WebhooksController#create` dispatches to `MembershipHandler#process` with the full attacker-controlled JSON body [4](#0-3) .
3. `MembershipHandler#find_or_create_team!` runs `Team.find_or_create_by!(github_id: params.team.id)` [5](#0-4) . If a `Team` row with that `github_id` already exists (e.g. belonging to `victim-org`), ActiveRecord's `find_or_create_by!` **finds** it and returns it immediately; the block (which would set `team.organization = params.organization.login`) only runs on creation, so it is skipped entirely — the existing team's `organization` attribute is never re-checked or updated.
4. `MembershipHandler#process` then does `team.add_member(User.find_or_create_by_login!(params.member.login))` [6](#0-5) , writing a `Membership` row for the attacker's chosen GitHub login into the victim's team, regardless of which organization's secret actually authenticated the request.
5. `User#authorized?` grants global Shipit access to any user with a membership in a team listed in `Shipit.github_teams` [1](#0-0) .

None of the documented guards intercept this: `verify_signature` only proves "this request was signed by *some* org configured in Shipit," not "this org owns this team ID"; `ExplicitParameters` schema only validates types/presence, not cross-tenant scoping [7](#0-6) ; there is no `require_permission!`/`force_github_authentication` check in this controller at all, since it's a public webhook endpoint.

### Impact Explanation
An attacker who legitimately administers one tenant org in a multi-org Shipit deployment (`docs/setup.md` "Using Multiple Github Applications" config) [8](#0-7)  can add arbitrary GitHub logins to any other tenant's `Shipit.github_teams` team, provided they can learn/guess that team's numeric GitHub `github_id`. This is a cross-tenant authorization escalation: it grants the attacker (or anyone they name) full authenticated access to the victim org's stacks, deploys, and API, matching the "escalation into `Shipit.github_teams` authorization" High-severity category (arguably Critical since it is an authentication/authorization bypass across tenant boundaries). It is repeatable against any team whose `github_id` is known and is not scoped to a single request.

### Likelihood Explanation
Requires: (a) a multi-org Shipit deployment with at least one other legitimately configured tenant, (b) that tenant's admin acting maliciously (or their webhook secret being leaked), and (c) knowledge of the victim team's GitHub `github_id` (a small integer, potentially discoverable via GitHub's team API, git history, or Shipit's own data). Given (a) and (b), the attack requires only a single crafted HTTP POST with a valid HMAC signature computed from a secret the attacker already legitimately possesses — no cryptographic bypass needed. This is feasible but conditioned on a malicious/compromised tenant, which is a real but narrower threat model than "any internet user."

### Recommendation
In `find_or_create_team!`, scope the lookup by both `github_id` and `organization` (matching `params.organization.login`), and reject/ignore the event (or raise) if a `Team` with that `github_id` already exists under a different organization, e.g.:
```ruby
def find_or_create_team!
  team = Team.find_by(github_id: params.team.id)
  if team && team.organization != params.organization.login
    raise ArgumentError, "team #{params.team.id} does not belong to organization #{params.organization.login}"
  end
  Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login) do |t|
    t.github_team = params.team
  end
end
```

### Proof of Concept
minitest (`test/controllers/webhooks_controller_test.rb` style, `ActionDispatch::IntegrationTest` or `ActionController::TestCase` with a second stubbed GitHub app for `attacker-org`):
1. Setup: create `shipit_teams(:shopify_developers)` fixture with `organization: 'shopify'`, `github_id: X`.
2. Stub `Shipit.github(organization: 'attacker-org')` (or configure a second org in test secrets) so `verify_webhook_signature` returns `true` for the crafted payload+signature, matching real multi-org config.
3. POST `/webhooks` with header `X-Github-Event: membership`, body:
```json
{"action":"added","team":{"id":X,"name":"x","slug":"x","url":"x"},"organization":{"login":"attacker-org"},"member":{"login":"attacker"}}
```
4. Assert before: `Team.find_by(github_id: X).organization == 'shopify'` and `Membership.exists?(team_id: X, user: User.find_by(login: 'attacker')) == false`.
5. Assert after: `Membership.exists?(team_id: X, user: User.find_by(login: 'attacker')) == true` and `User.find_by(login: 'attacker').authorized? == true`, even though the request was signed by `attacker-org`, not `shopify`.

### Citations

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
