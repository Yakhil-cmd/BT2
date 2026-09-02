### Title
Membership webhook handler resolves `Team` by a globally-unique GitHub `team.id` without scoping to the authenticating organization, allowing cross-organization team-membership injection - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to check against based on a field taken from the *unverified* payload (`repository.owner.login` / `organization.login`), then verifies the HMAC using that organization's own `webhook_secret`. Once verified, `MembershipHandler#find_or_create_team!` looks up/creates the affected `Team` using only `params.team.id` — a value fully controlled by the payload — with no scoping to the organization that authenticated the request. This breaks the equality that should hold: `organization whose secret authenticated the request == organization that owns the Team record being mutated`.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb#verify_signature` picks the `GitHubApp` (and therefore the HMAC secret) to validate the delivery against using `repository_owner`, itself derived from the JSON body: [1](#0-0) [2](#0-1) 

For `membership` events this resolves to `params.dig('organization', 'login')`. Because a Shipit installation can (and, per the documented "Using Multiple GitHub Applications" setup, is expected to) manage several distinct organizations each with its own `webhook_secret`, an attacker who legitimately controls the GitHub App/webhook installation for *one* configured organization (org A) can produce a validly-signed `membership` payload for org A.

The handler that then processes this validated event does not re-check that the team it is about to mutate belongs to org A: [3](#0-2) 

`Team.find_or_create_by!(github_id: params.team.id)` looks the team up purely by the attacker-supplied numeric `team.id`. GitHub team IDs are global, not org-scoped identifiers, and there is no uniqueness/scope constraint tying this lookup back to `repository_owner`/the authenticating org. The `organization:` field is only assigned inside the `create` block, i.e. only when the team doesn't already exist — if the `team.id` supplied collides with an *already existing* `Team` row (e.g. a privileged team such as `Shopify/developers` that is part of `Shipit.github_teams`), `find_or_create_by!` returns that existing record untouched, and `team.add_member(member)` (or `team.members.delete(member)`) is executed against it: [4](#0-3) [5](#0-4) 

`member` is a GitHub login fully controlled by the attacker's payload (`params.member.login`), auto-vivified via `User.find_or_create_by_login!`. The resulting `Membership` row is what `User#authorized?` checks against `Shipit.github_teams`: [6](#0-5) [7](#0-6) 

So: **before** the attack, `repository_owner`/org A's secret authorizes only mutations relevant to org A's own `Team` rows (id scoped to org A's github_id namespace in practice). **After** the attack, org A's secret can add an arbitrary GitHub login as a member of any `Team` row already present in the database (including one belonging to org B, whose `github_teams`/`oauth.teams` gate access to the whole Shipit instance), because the lookup key (`github_id`) is never checked against the authenticating org.

This is the direct structural analog of the Compound finding: a value (`team.id` here, unclaimed rewards there) that is *acted upon* by the write path (`getPositionTVL`/`Team.find_or_create_by!`) is never covered/validated against the binding that should constrain it (collateral+debt accounting/organization-of-record), producing an incorrect, attacker-influenced result.

### Impact Explanation
This directly matches the "escalation into `Shipit.github_teams` authorization" High-severity category: an actor who only has legitimate control of one configured GitHub organization's webhook (a much lower trust tier than a Shipit account, `ApiClient` token, or `github_teams` member) can grant themselves (or any GitHub login they choose) membership in a `Team` that gates access to the entire Shipit application via `User#authorized?`, bypassing the intended requirement of being verified through GitHub org/team membership of the actually-authorized organization.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (explicitly documented/supported), (2) the attacker controls or compromises the GitHub App/webhook secret of any one configured organization (not necessarily the privileged one gating access), and (3) knowledge or guessability of the numeric GitHub `team.id` of the privileged team (visible via GitHub's public API/UI for the target org's team, or observable from prior webhook traffic/logs). No Shipit session, `ApiClient` token, or `github_teams` membership is required — only the ability to sign a webhook payload for some org in the install. This is a plausible, low-privilege attack path in any multi-org Shipit deployment.

### Recommendation
Scope the `Team.find_or_create_by!` lookup by both `github_id` and the authenticating organization (e.g., `find_or_create_by!(github_id: params.team.id, organization: repository_owner_from_signed_org)`), and reject/raise if an existing `Team` with that `github_id` belongs to a different organization than the one whose secret verified the request. More generally, `MembershipHandler` should receive and trust the organization value only from the already-verified `verify_signature` context, not re-derive/re-trust it from `params.organization.login` for record matching.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `OrgA` (attacker-controlled GitHub App/webhook) and `OrgB` (contains the privileged `Team` referenced by `Shipit.github_teams`, e.g. `OrgB/developers` with `github_id = 555`).
2. Attacker crafts a `membership` webhook payload:
```json
{
  "action": "added",
  "team": { "id": 555, "name": "developers", "slug": "developers", "url": "https://api.github.com/teams/555" },
  "organization": { "login": "OrgA" },
  "member": { "login": "attacker" }
}
```
3. Attacker signs this payload with `OrgA`'s legitimate `webhook_secret` and POSTs it to `/webhooks`.
4. `verify_signature` resolves `repository_owner` → `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the HMAC check passes (valid signature for OrgA).
5. `MembershipHandler#process` runs `Team.find_or_create_by!(github_id: 555)`, matching the existing `OrgB/developers` `Team` row, and calls `team.add_member(User.find_or_create_by_login!("attacker"))`.
6. If `OrgB/developers` is part of `Shipit.github_teams`, the newly created/linked `attacker` `User` now passes `User#authorized?` and gains access to the Shipit UI/instance despite never being a member of any privileged GitHub organization or team.

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```
