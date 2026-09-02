### Title
Cross-tenant Team membership write via `Shipit::Webhooks::Handlers::MembershipHandler` bypasses org-binding, enabling `Shipit.github_teams` authorization escalation - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` only proves that a `membership` webhook was signed with the secret of the organization named in the payload's own `organization.login` (or `repository.owner.login`) field; it never proves that the `team` object embedded in the same payload actually belongs to that organization. `MembershipHandler#find_or_create_team!` looks up/creates `Team` rows keyed solely by `params.team.id`, so an attacker who legitimately controls one org (and therefore knows *that org's* `webhook_secret`) can send a validly-signed webhook that mutates the membership of a `Team` row belonging to a completely different, victim organization.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`team.organization (existing DB row for params.team.id) == organization used by verify_signature (repository_owner == params.organization.login)`.

Path:
1. `Shipit::WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`), which falls back to `params.dig('organization', 'login')`. It calls `Shipit.github(organization: repository_owner)` and checks `verify_webhook_signature` against **that** org's `webhook_secret` only [1](#0-0) [2](#0-1) .
2. Once the signature check passes, `create` hands the *entire raw payload* to every registered handler for the event, unmodified: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .
3. `MembershipHandler` only validates types via `ExplicitParameters` (`team.id: Integer`, `organization.login: String`, etc.) — no cross-field/ownership constraint [4](#0-3) .
4. `find_or_create_team!` resolves the target `Team` **only** by `params.team.id` (the GitHub numeric team id), and the block that would set `team.organization = params.organization.login` only executes on record creation, not when an existing team is found: `Team.find_or_create_by!(github_id: params.team.id) do |team| ... end` [5](#0-4) .
5. `process` then unconditionally calls `team.add_member(member)` or `team.members.delete(member)` on whatever `Team` was resolved, with `member` built from `params.member.login` — an attacker-controlled string that `User.find_or_create_by_login!` will happily create/fetch [6](#0-5) .

Exploit: An attacker who administers "attacker-owned-org" (and therefore knows its own `webhook_secret`, configured legitimately in Shipit's multi-org secrets) sends `POST /webhooks` with `X-Github-Event: membership`, a correctly computed `X-Hub-Signature` for their own secret, and a payload of the form:
```json
{"action":"added","organization":{"login":"attacker-owned-org"},
 "team":{"id":<victim-org's oauth-restricted team github_id>,"name":"x","slug":"x","url":"http://x"},
 "member":{"login":"attacker-github-login"}}
```
`repository_owner` resolves to `attacker-owned-org`, signature verification passes against the attacker's own known secret, and `MembershipHandler` then adds the attacker's `User` to the pre-existing `Team` row identified by the victim's team id — a team that belongs to a different organization entirely.

Why existing guards fail: `verify_signature` binds "who signed this request" to "which org's secret was used," but it never re-validates that `team`/`organization` sub-objects inside the payload are consistent with each other; `drop_unhandled_event` does not filter `membership`; the `ExplicitParameters` schema only checks types, not ownership; `Membership` model validation only enforces `user_id` uniqueness scoped to `team_id`, not organizational consistency [7](#0-6) .

### Impact Explanation
If the victim team's numeric github id is one of the ids returned by `Shipit.github_teams` (an oauth-restricted team configured via `github.oauth.teams`, pre-populated as `Team` rows by `Team.find_or_create_by_handle`) [8](#0-7) , then adding the attacker's own GitHub login as a member of that team flips `User#authorized?` to `true` for the attacker's account: `@authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [9](#0-8) . This is an authorization-scope escalation across organizational tenants — the attacker's own, unrelated org's webhook secret is used to grant themselves membership in a Shipit-gating team belonging to a different org, bypassing the intended team-restricted login gate. This matches the High-severity category "escalation into `Shipit.github_teams` authorization." It is repeatable against any known/discoverable team id and reversible/replayable (`action: removed` can also be used to strip legitimate members from a victim's team, denying them access).

### Likelihood Explanation
Preconditions: the attacker must operate at least one organization that is configured as a legitimate multi-tenant entry in Shipit's `secrets.github` (with its own `webhook_secret`, which as that org's own administrator they know), and must know or guess the numeric GitHub `team.id` of a target team that Shipit already tracks (typically an `oauth.teams`-configured team, which is discoverable via GitHub's public team API for public teams, or leaked in other webhook payloads Shipit has previously accepted). No Shipit session, API token, or any secret belonging to the victim org is required — only the attacker's own legitimately-provisioned org credentials. This is a low-cost, fully repeatable HTTP request once the team id is known.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that any existing `Team` resolved by `github_id` has `organization == params.organization.login` (case-insensitively) before performing any membership mutation; reject/log the event otherwise. More generally, `WebhooksController#verify_signature`'s resolved `repository_owner`/organization should be threaded into every handler and checked against every organization-bearing sub-object (`team`, `repository.owner`, `organization`) in that payload before any write occurs, rather than allowing handlers to trust unrelated payload substructures merely because the outer signature matched.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
```ruby
test ":membership webhook signed by org A can mutate a team belonging to org B" do
  # Arrange: a team that "belongs" to org B already exists in the DB
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify'

  @request.headers['X-Github-Event'] = 'membership'

  payload = {
    action: 'added',
    organization: { login: 'attacker-owned-org' }, # org A, distinct from victim_team.organization
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    member: { login: 'attacker' }
  }.to_json

  # Signature verification is scoped ONLY to org A ('attacker-owned-org'),
  # never compared against victim_team.organization ('shopify')
  Shipit.github(organization: 'attacker-owned-org').expects(:verify_webhook_signature).returns(true)

  assert_difference -> { victim_team.memberships.count }, 1 do
    post :create, body: payload, as: :json
  end

  assert_response :ok
  assert_equal 'shopify', victim_team.reload.organization # unchanged: team never belonged to org A
  assert victim_team.members.exists?(login: 'attacker')   # yet attacker was still added
end
```
Both sides of the claimed binding — `Shipit.github(organization: 'attacker-owned-org')` (derived purely from the payload's outer `organization.login`) versus the `team_id`-keyed write with no comparison to that resolved organization — are asserted directly, demonstrating the divergence.

### Citations

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

**File:** app/models/shipit/membership.rb (L1-9)
```ruby
# frozen_string_literal: true

module Shipit
  class Membership < Record
    belongs_to :team, required: true
    belongs_to :user, required: true

    validates :user_id, uniqueness: { scope: :team_id }
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
