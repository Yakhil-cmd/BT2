### Title
Cross-tenant `Team` membership escalation via `MembershipHandler#find_or_create_team!` github_id collision - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` authenticates a `membership` webhook only against the organization named in the payload (`repository_owner`, which falls back to `organization.login`), never against the organization that actually owns the `Team` record being mutated. Because `MembershipHandler#find_or_create_team!` looks up teams solely by `github_id` and `Team.find_or_create_by!` skips the initializer block when the record already exists, an attacker who controls any onboarded organization's own legitimate `webhook_secret` can add an arbitrary GitHub login as a member of a pre-existing `Team` belonging to a completely different organization, as long as they guess/know its `github_id`.

### Finding Description
The broken binding is: `organization_that_signed_the_request == organization_that_owns(Team.find_by(github_id: params.team.id))`. This is never checked anywhere in the call path.

- `repository_owner` reads `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . For a `membership` event with no `repository` key, this resolves to the attacker's own `organization.login`.
- `verify_signature` calls `Shipit.github(organization: repository_owner)` and verifies the signature with that organization's own `webhook_secret` [2](#0-1) . Since the attacker signs with their own org's real secret, this check trivially passes and provides no cross-tenant guarantee.
- `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.github_team = params.team; team.organization = params.organization.login }` [3](#0-2) . `find_or_create_by!` only runs the block when creating a new row; if a `Team` with that `github_id` already exists (e.g. one belonging to a different organization and referenced in `Shipit.github_teams`), the existing record is returned unchanged and the block (which would set `organization`) never executes.
- `process` then unconditionally does `team.add_member(member)` for `action == 'added'`, where `member = User.find_or_create_by_login!(params.member.login)` [4](#0-3) . Nothing compares `params.organization.login` against the found `team.organization`.

Exploit flow: attacker owns `attacker-org` (onboarded in `Shipit.secrets.github` with its own `webhook_secret`). They send `POST /webhooks` with `X-Github-Event: membership`, body:
```json
{"action":"added","team":{"id":<github_id of victim Team>,"name":"x","slug":"x","url":"https://example.com"},"organization":{"login":"attacker-org"},"member":{"login":"attacker_github_login"}}
```
signed with `attacker-org`'s own real `webhook_secret`. Signature verifies (against attacker's own secret), the handler finds the victim's pre-existing `Team` row by `github_id`, and adds `attacker_github_login`'s `User` (created on the fly via `User.find_or_create_by_login!`) as a member of that victim team.

If that victim team is one of `Shipit.github_teams` (`github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }` [5](#0-4) ), the attacker's GitHub account gains `authorized?` status, since `authorized?` is `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) .

Existing guards do not stop this: `drop_unhandled_event` only checks that a handler exists for the event type [7](#0-6) ; `ExplicitParameters` schema in `MembershipHandler` only validates types/presence, not organizational ownership [8](#0-7) ; and `Handler` base class provides no cross-check between `payload['organization']` and the resolved `Team.organization` [9](#0-8) .

### Impact Explanation
An attacker who only controls an unrelated, onboarded GitHub organization (and thus its own legitimate webhook secret — a low, self-serve precondition, not a Shipit or victim secret) can inject arbitrary GitHub logins into any other organization's `Team` record, provided they know or guess that team's numeric GitHub `team.id`. If the targeted `Team` is part of `Shipit.github_teams`, this is a direct authorization escalation: the attacker's own (or any chosen) GitHub account becomes `authorized?` in Shipit, unlocking deploy/rollback/merge actions gated behind `require_permission!`/team authorization. This is repeatable against any `Team` row for any organization onboarded in `Shipit.secrets.github`, and the blast radius spans every tenant organization hosted by the same Shipit instance. This matches the "High — escalation into `Shipit.github_teams` authorization" category.

### Likelihood Explanation
Preconditions: (1) the Shipit instance must host more than one onboarded organization in `Shipit.secrets.github` (multi-tenant deployment, explicitly called out as the threat model in the question); (2) the attacker needs their own organization's `webhook_secret`, which they inherently possess as the org's owner — no Shipit or victim secret is required; (3) the attacker needs to know/guess the numeric `github_id` of the victim `Team` — these IDs are visible via GitHub's public API for teams the attacker can observe, or via other Shipit UI/API surfaces exposing team info, and are not high-entropy secrets. Cost to the attacker is a single crafted HTTP POST; the exploit is fully repeatable and requires no live GitHub interaction to demonstrate.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that the found (or newly created) `Team#organization` matches `params.organization.login` before proceeding, and reject/abort (or re-key the lookup) when they diverge — e.g. scope the lookup by both `github_id` and `organization`, or explicitly check `team.organization == params.organization.login` and raise/return early otherwise. Additionally, `WebhooksController#verify_signature` should not accept a payload's own `organization.login` as authoritative for events that mutate cross-referenced records; the trust boundary should be pinned to the specific organization whose secret was used, and handlers must not let that same value drive `find_or_create_by!` lookups keyed on attacker-controlled, potentially colliding IDs.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/membership_handler_test.rb (or webhooks_controller_test.rb)
test "membership event signed by org A cannot add members to org B's pre-existing Team" do
  victim_team = shipit_teams(:shopify_developers) # belongs to organization "shopify", github_id already set
  assert_equal 'shopify', victim_team.organization

  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulate attacker-org's own valid signature
  attacker_payload = {
    action: 'added',
    team: { id: victim_team.github_id, name: 'x', slug: 'x', url: 'https://example.com' },
    organization: { login: 'attacker-org' }, # no 'repository' key, matches real membership payload shape
    member: { login: 'attacker_login' }
  }

  request.headers['X-Github-Event'] = 'membership'

  assert_no_difference -> { Team.count } do
    assert_difference -> { victim_team.reload.members.count }, 1 do
      post :create, body: attacker_payload.to_json, as: :json
    end
  end

  # Binding check (should hold, currently fails):
  # organization_that_signed(attacker-org) == organization_that_owns(victim_team)("shopify") -> false
  # but the write to victim_team.members still happened, proving the binding is not enforced.
  assert_includes victim_team.reload.members.map(&:login), 'attacker_login'
end
```
This demonstrates the payload signed under `attacker-org`'s own secret (`organization.login == 'attacker-org'`) mutates `shopify`'s pre-existing `Team` membership because `find_or_create_by!(github_id:)` matches the existing row and `add_member` runs regardless of organization mismatch.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-28)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-42)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L1-41)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class Handler
        class << self
          attr_reader :param_parser

          def params(&block)
            @param_parser = ExplicitParameters::Parameters.define(&block)
          end
        end

        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
    end
  end
```
