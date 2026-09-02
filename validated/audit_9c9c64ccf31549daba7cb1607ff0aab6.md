### Title
Cross-organization Team hijack via unscoped `github_id` lookup in `MembershipHandler#find_or_create_team!` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` resolves the target `Team` solely by `github_id` and resolves the `User` solely by an attacker-supplied `login`, then unconditionally creates a `Membership` between them. Because `Team.find_or_create_by!(github_id: params.team.id)` does not re-validate the `organization` on an existing record, any organization independently onboarded to a multi-org Shipit install can reuse a *known* `github_id` belonging to a **different, more privileged** organization's team to attach an arbitrary login to that sensitive team, escalating into `Shipit.github_teams` authorization.

### Finding Description
The equality the code must, but does not, enforce is:
`repository_owner` (the organization whose `webhook_secret` validated the request, derived from `params.organization.login` via `WebhooksController#repository_owner`) `==` the `organization` that actually owns `Shipit::Team#github_id == params.team.id`.

Trace:
- `WebhooksController#verify_signature` selects the signing app via `Shipit.github(organization: repository_owner)`, where `repository_owner` falls back to `params.dig('organization','login')` for membership events (no `repository` key present) — [1](#0-0) [2](#0-1) . This only proves the request came from *some* onboarded organization — the one named in `organization.login` — nothing more.
- `MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) do |team| team.organization = params.organization.login end` [3](#0-2) . The `organization=` assignment inside the block only runs **on creation**. If a `Team` row with that `github_id` already exists (e.g. a legitimate, sensitive team belonging to org "shopify" that is part of `Shipit.github_teams`), `find_or_create_by!` simply returns the existing record — the mismatch between the requesting organization and the team's real `organization` is never checked.
- `member = User.find_or_create_by_login!(params.member.login)` resolves/creates a `User` purely from the attacker-chosen `login` field, fetching profile data via the **global** `Shipit.github.api` (not the requesting org's app) [4](#0-3) , and returns that record with no cross-check against the team's real GitHub roster.
- `team.add_member(member)` then persists a `Membership` linking the attacker-named login to the team object found above [5](#0-4) .

Exploit flow (multi-org deployment, documented and supported in `docs/setup.md`'s "Using Multiple Github Applications"): an attacker who genuinely administers Organization B (onboarded to this Shipit instance with its own `webhook_secret`, but not itself a member of `Shipit.github_teams`) sends `POST /webhooks` with `X-Github-Event: membership`, `organization.login: "org-b"` (signed with org‑b's real, attacker-known secret), `team: { id: <numeric github_id of a sensitive team already owned by org "shopify"> }`, and `member: { login: "<any-github-login>" }`. `verify_signature` succeeds because it only checks org‑b's own secret against org‑b's own claimed identity. `find_or_create_team!` finds the pre-existing "shopify" team purely by `github_id` and ignores that the request came from org‑b. The arbitrary login is attached to that team's membership, and if `Shipit.github_teams` includes it, `User#authorized?` (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`) now returns true for that login [6](#0-5) .

None of the existing guards prevent this: `verify_signature` authenticates the *sender org*, not the *team ownership claim*; `drop_unhandled_event`/`ExplicitParameters` only validate payload shape (`team.id`, `organization.login`, `member.login` types) [7](#0-6) ; and there is no live GitHub API call to confirm the claimed team/member relationship.

### Impact Explanation
An attacker who controls one legitimately-onboarded but low-privilege organization in a multi-org Shipit deployment can grant an arbitrary GitHub login (their own account, or a real, already-privileged operator's login if it collides with an existing `User` row holding a `github_access_token`) membership in a `Shipit.github_teams`-scoped team belonging to a different organization. This bypasses `User#authorized?` and grants access to protected stacks/actions gated by team membership — matching the High severity category "escalation into `Shipit.github_teams` authorization." It is repeatable for any known team `github_id` and any login, and is not limited to a single repository/stack — it affects the tenant-wide authorization model.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment where the attacker's own organization is one of the configured `secrets.github` orgs (a documented configuration), (2) the attacker knows the numeric GitHub `github_id` of the target team (discoverable via public GitHub team/org APIs or prior observation), and (3) a `Team` row for that `github_id` already exists in Shipit's database (created by a legitimate prior sync). Given these preconditions, the attack costs only a single crafted HTTP POST signed with a secret the attacker already legitimately possesses for their own org — no stolen secrets required. In a single-org Shipit deployment (the common case) this path is not exploitable, since the attacker would need the one global `webhook_secret`, which is out of scope per the threat model.

### Recommendation
Scope the `Team` lookup by both `github_id` and `organization`, and reject/log a mismatch instead of silently reusing an existing team from a different organization:
```ruby
def find_or_create_team!
  team = Team.find_by(github_id: params.team.id)
  if team && team.organization != params.organization.login.downcase
    raise ArgumentError, "team #{params.team.id} does not belong to organization #{params.organization.login}"
  end
  team || Team.create!(github_team: params.team, organization: params.organization.login)
end
```
Additionally, consider verifying `params.member.login` against a live `GET /orgs/:org/teams/:slug/memberships/:username` call scoped to the requesting organization's app before creating the `Membership`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`), extending the existing membership fixtures:
```ruby
test ":membership from a different organization cannot attach members to another org's team" do
  other_org_team = shipit_teams(:shopify_developers) # belongs to "shopify", in Shipit.github_teams
  Shipit.stubs(:github_teams).returns([other_org_team])

  @request.headers['X-Github-Event'] = 'membership'
  # Simulate org "attacker-org" being a separately onboarded, legitimately signed org.
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # attacker-org's own valid secret

  payload = {
    action: 'added',
    organization: { login: 'attacker-org' },
    team: { id: other_org_team.github_id, name: other_org_team.name, slug: other_org_team.slug, url: other_org_team.api_url },
    member: { login: 'victim-operator' }
  }.to_json

  assert_difference -> { Shipit::Membership.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end

  user = Shipit::User.find_by(login: 'victim-operator')
  assert_includes other_org_team.members.reload, user
  assert user.authorized?, "attacker-controlled org attached an arbitrary login to a Shipit.github_teams team it does not own"
end
```
This asserts the broken binding directly: the team's real `organization` ("shopify") never matches the requesting `organization.login` ("attacker-org"), yet the `Membership` and resulting `authorized?` grant are created anyway.

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

**File:** app/models/shipit/user.rb (L22-28)
```ruby
    def self.find_or_create_by_login!(login)
      find_or_create_by!(login:) do |user|
        # Users are global, any app can be used
        # This will not work for users that only exist in an Enterprise install
        user.github_user = Shipit.github.api.user(login)
      end
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
