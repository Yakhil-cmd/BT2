### Title
Cross-organization `Team` membership forgery via unvalidated `github_id` lookup in `MembershipHandler` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` resolves a `Team` purely by the numeric `github_id` supplied in the webhook payload, without checking that the request's verified organization matches the `Team#organization` already stored on that row. An attacker who controls a second GitHub organization already onboarded to the same Shipit instance (and therefore has a `webhook_secret` for it) can sign a `membership` event for their own org but set `team.id` to the `github_id` of a team belonging to a different, victim organization, causing `team.add_member(member)` to insert a `Membership` for that victim team, without ever touching the victim org's secret.

### Finding Description
The broken binding, stated explicitly:
`WebhooksController#verify_signature` selects the secret to check via `Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) [2](#0-1) . For a `membership` event there is no `repository` key, so `repository_owner` is exactly `params['organization']['login']` — i.e. the *same attacker-controlled field* that determines which secret verifies the request. This only proves "the sender knows the secret for the org named in `organization.login`" — it proves nothing about `params.team.id`.

`MembershipHandler#find_or_create_team!` then does:
```ruby
Team.find_or_create_by!(github_id: params.team.id) do |team|
  team.github_team = params.team
  team.organization = params.organization.login
end
``` [3](#0-2) 
The block (which sets `organization`) only runs on **create**. If a `Team` row with that `github_id` already exists (e.g. a legitimate team from `victim-org`), `find_or_create_by!` returns the existing record untouched — `team.organization` stays `victim-org`, regardless of what `organization.login` was in the current, attacker-signed payload. `process` then calls `team.add_member(User.find_or_create_by_login!(params.member.login))` [4](#0-3) , and `Team#add_member` unconditionally appends the member [5](#0-4) , persisting a `Membership` row.

So the required equality — "the organization whose secret verified this request" **must equal** "the organization owning the `Team` row being mutated" — is never checked. `repository_owner` (used to pick the verifying secret) and `Team#organization` (the value bound at the team's original creation) are independent once the team already exists.

Attack: attacker owns `attacker-org`, already configured in Shipit with its own `webhook_secret` (multi-tenant Shipit setup). Attacker sends a correctly-HMAC-signed `POST /webhooks` with `X-Github-Event: membership`, body:
```json
{"action":"added","organization":{"login":"attacker-org"},
 "team":{"id":<victim_team_github_id>,"name":"x","slug":"x","url":"http://x"},
 "member":{"login":"attacker"}}
```
`verify_signature` passes because it is verified against `attacker-org`'s own secret, which the attacker legitimately possesses [1](#0-0) . `find_or_create_team!` looks up the existing victim `Team` by `github_id` (found, not created), ignoring `organization: 'attacker-org'` in the payload [3](#0-2) . `User.find_or_create_by_login!('attacker')` creates/finds the attacker's own `User` row [6](#0-5) . `team.add_member(member)` inserts a `Membership(user: attacker, team: victim_team)`.

Existing guards do not prevent this: `verify_signature` only authenticates "the sender knows some org's secret," not "which team/org the payload content refers to"; the `ExplicitParameters` schema in the handler only enforces types/presence, not cross-field consistency [7](#0-6) ; `drop_unhandled_event` and `check_if_ping` are irrelevant; there is no `require_permission!`/`force_github_authentication` in this write path since it's a webhook, not a session request.

### Impact Explanation
If `victim_team` is one of the teams listed in `Shipit.github_teams` (the configured authorization gate), `User#authorized?` becomes true for the attacker's forged `User` because it checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [8](#0-7) . This is a High/Critical escalation into `Shipit.github_teams` authorization — the attacker gains deploy/stack permissions gated by team membership, for an organization they do not control, from an org they do control. This is repeatable against any `Team#github_id` the attacker can learn (team IDs are visible via GitHub's public API for teams under organizations, or via prior Shipit UI/API exposure) and against any organization onboarded into the same multi-tenant Shipit instance.

### Likelihood Explanation
Preconditions: (1) Shipit instance configured for multiple GitHub organizations (each with distinct `webhook_secret`s) — a supported, documented Shipit deployment mode; (2) attacker legitimately administers one of those organizations (`attacker-org`), which is within the stated threat model (they can emit correctly signed webhooks for their own org); (3) attacker knows/guesses the numeric `github_id` of a victim team. Cost is a single crafted HTTP POST; no session, token, or victim secret is required. This is fully repeatable and scriptable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, validate that an existing `Team`'s `organization` matches `params.organization.login` before performing any mutation (`add_member`/`delete`), and raise/drop the event on mismatch instead of silently operating on a team from a different org. More generally, bind `Team` lookups to `(github_id, organization)` rather than `github_id` alone, and verify in the handler that the org used to authenticate the webhook (`repository_owner`) equals the `organization.login` in the payload it is now allowed to mutate.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (illustrative)
test ":membership from a different verified org cannot mutate another org's team" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify'
  attacker_org_secret = 'attacker-secret'
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    stub(verify_webhook_signature: true)
  )

  payload = {
    action: 'added',
    organization: { login: 'attacker-org' },
    team: { id: victim_team.github_id, name: 'x', slug: 'x', url: 'http://x' },
    member: { login: 'attacker' }
  }.to_json

  @request.headers['X-Github-Event'] = 'membership'
  post :create, body: payload, as: :json

  # Binding under test: verifying org must equal the org owning the mutated team
  assert_equal 'shopify', victim_team.reload.organization
  # Vulnerable behavior observed today:
  assert Membership.exists?(team: victim_team, user: Shipit::User.find_by(login: 'attacker'))
end
```
This demonstrates the payload verified under `attacker-org`'s secret still writes a `Membership` for `victim_team`, whose `organization` remains `'shopify'` — the equality the binding requires never holds, yet the write succeeds.

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
