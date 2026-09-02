### Title
`MembershipHandler#process` binds Team lookup to attacker-supplied `team.id` only, letting a cross-org webhook add an arbitrary member to a privileged `Team` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#process` resolves the target `Team` solely by `params.team.id` via `Team.find_or_create_by!(github_id: params.team.id)`, without verifying that `params.organization.login` matches the `organization` already stored on that `Team` row. Because `WebhooksController#verify_signature` selects the HMAC secret to check based on the attacker-controlled `organization.login` field in the same payload, an attacker who administers any org configured in Shipit can sign a `membership` webhook with their own org's legitimate secret while naming a `team.id` belonging to a different (privileged) org's team, causing a cross-org `Membership` row to be created.

### Finding Description
The broken binding is: `Team.find_or_create_by!(github_id: params.team.id).organization == params.organization.login` is assumed but never checked.

Path:
- `WebhooksController#verify_signature` computes `repository_owner` from the payload itself (`params.dig('organization', 'login')` for membership events, since there is no `repository` key) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) [2](#0-1) . This authenticates that the request truly came from the org named in the payload, using that org's own configured `webhook_secret` — it does not authenticate anything about the `team` sub-object.
- `MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { ... }` [3](#0-2) . The block (which sets `team.organization = params.organization.login`) only runs on record creation; if a `Team` with that `github_id` already exists (e.g. a privileged team such as `shopify_developers`), `find_or_create_by!` returns the *existing* row unchanged, regardless of which organization is named in the current payload.
- `team.add_member(member)` unconditionally appends the resolved `User` (created via attacker-controlled `params.member.login`) to that team's `members` [4](#0-3) [5](#0-4) .
- Team membership is used directly for application authorization: `User#authorized?` grants access if `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) .

Attack: attacker administers/owns an org (Org B) already registered with Shipit (so they can trigger a genuine webhook signed with Org B's `webhook_secret`, or otherwise control an endpoint that emits a signed `membership` event for Org B). They craft a `membership` webhook body: `action: "added"`, `team: {id: <target Team's github_id belonging to Org A>, name, slug, url}`, `organization: {login: "OrgB"}`, `member: {login: <attacker-chosen login>}`, sign it with Org B's `webhook_secret`, and POST it to `/webhooks` with `X-Github-Event: membership`. `verify_signature` succeeds because everything about Org B is genuine. `find_or_create_team!` then resolves to Org A's real `Team` (matched purely by `github_id`), and the attacker-chosen user becomes a member of Org A's team.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) only check that the HTTP request's signature matches the org named inside the body itself — none of them tie `team.id` to `organization.login`, so the divergence is real.

### Impact Explanation
A successful request creates a `Membership` row binding an attacker-controlled `User` to a `Team` belonging to a different organization than the one that authenticated the webhook. If that `Team` is part of `Shipit.github_teams`, the attacker-controlled user immediately satisfies `User#authorized?` and gains authenticated access to the entire Shipit instance (stacks, tasks, deploy triggers subject to further permission checks), which is an authorization escalation into `Shipit.github_teams`. The attack is repeatable against any `Team` whose `github_id` the attacker can guess, and is not limited to one repository/stack — it is a cross-tenant authorization primitive in a multi-org Shipit deployment.

### Likelihood Explanation
Preconditions: Shipit must be configured for multiple GitHub organizations (multiple `webhook_secret`s in `secrets.yml`, as supported by `Shipit.github(organization:)`), and the attacker must control/administer at least one of those registered orgs (satisfying "own a repository/org that can emit webhooks") while targeting a `Team` from a different registered org. The attacker also needs the target team's GitHub `team.id`, which is a GitHub-global integer — not secret, and enumerable/observable in many cases (e.g., visible in GitHub UI/API responses the attacker can view for public teams, or brute-forceable given the small ID space in practice). Given these preconditions, the attack costs a single crafted HTTP POST and is fully repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!` (and analogous handlers), verify that an existing `Team` matched by `github_id` has `organization == params.organization.login` before performing any membership mutation; raise/reject the event on mismatch instead of silently reusing the found record. More generally, webhook handlers that mutate cross-referenced records by a GitHub-assigned numeric ID should always additionally check the record's already-persisted "owning organization" against the organization that was authenticated for this specific request.

### Proof of Concept
```ruby
# test/models/webhooks/membership_handler_test.rb (illustrative)
test "cross-org membership webhook cannot add a member to another org's team" do
  privileged_team = shipit_teams(:shopify_developers) # organization == 'shopify'
  attacker_org = 'attacker-org' # configured in Shipit secrets with its own webhook_secret

  payload = {
    action: 'added',
    team: {
      id: privileged_team.github_id, # guessed/brute-forced to collide
      name: 'developers',
      slug: 'developers',
      url: 'https://api.github.com/teams/999'
    },
    organization: { login: attacker_org },
    member: { login: 'attacker_controlled_login' }
  }.to_json

  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', attacker_org_webhook_secret, payload)

  assert_no_difference -> { privileged_team.members.count } do
    post :create, params: {}, body: payload,
      headers: { 'X-Github-Event' => 'membership', 'X-Hub-Signature' => signature }
  end
  # BEFORE FIX: attacker's user IS added -> assert_no_difference fails, proving the bug
  # binding under test: Team.find_by(github_id: privileged_team.github_id).organization == 'shopify'
  # vs the organization actually authenticated for this request == attacker_org
end
```

The binding to assert both before and after: `team.organization` (persisted, `'shopify'`) must equal the authenticated request's `organization.login` (`attacker_org`) before `add_member` runs; currently no such equality check exists in `find_or_create_team!`, which is the root cause.

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
