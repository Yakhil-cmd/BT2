Confirmed: `MembershipHandler.call(params)` directly instantiates and invokes `process` via `Handler.call` [1](#0-0) , so the model-level bug can be reproduced without going through `WebhooksController#verify_signature` at all — a pure unit test of `Team.find_or_create_by!`'s create-only block semantics.

### Title
`Team#organization` is only set on record creation, never re-synced on subsequent `find_or_create_by!` matches, silently masking cross-org membership writes - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` uses `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }`, where the block only executes when a new record is being built, not when an existing row is found. Consequently, once a `Team` row exists for a given `github_id`, any later `membership` event carrying a different `params.organization.login` for that same `github_id` writes a `Membership`/removes one without ever touching `team.organization`, leaving the column pointing at whichever org happened to create the row first.

### Finding Description
The claimed binding is: `Team#organization == organization of the most recent org that successfully wrote a Membership for this team`. Tracing `find_or_create_team!` at [2](#0-1)  shows the block passed to `find_or_create_by!` is Rails' standard "new-record initializer" block — it is invoked only on `Team.new` when no matching row exists, never on `find_by(github_id:)` hits. This is confirmed by `Team`'s schema/fixtures where `organization` is a plain persisted column set once at creation [3](#0-2) .

`MembershipHandler#process` then unconditionally calls `team.add_member(member)` or `team.members.delete(member)` based solely on `params.action`, using whatever `team` row was returned, regardless of whether `params.organization.login` matches the stored `team.organization` [4](#0-3) . There is no check anywhere in `MembershipHandler` comparing `params.organization.login` to `team.organization` before mutating `Membership` rows.

Given the precondition stated in the prompt (a legitimate `Team` row for `github_id=N` already exists with `organization = "real-org"`, and a subsequent forged `added` event for the same `github_id` arrives with `organization.login = "evil-org"`), `find_or_create_by!` finds the existing row, skips the block entirely, and `Membership` bookkeeping proceeds under a `Team` object whose `organization` column still reads `"real-org"`. Any downstream code or operator relying on `Team#organization` to attribute which org is currently managing/writing that team's membership (e.g. for auditing or scoping `github_hooks` via the `organization`-keyed association at [5](#0-4) ) will misattribute the write to `real-org`.

No existing guard intercepts this: `MembershipHandler` performs no organization-consistency check between `params.organization.login` and `team.organization`, and `find_or_create_by!`'s create-only block semantics are inherent Rails behavior, not something the codebase compensates for.

### Impact Explanation
This does not itself grant new write access — that is scoped to the underlying cross-org write already described — but it destroys the only column (`Team#organization`) that could be used to detect it after the fact. Anyone reviewing `Team#organization` to determine "who owns/last touched this team" will see the original creator's org, not the actual org that most recently wrote a `Membership` row. This compounds the cross-org write into an undetectable one, matching the audit-evasion framing in the prompt. It is repeatable against any `Team` row for as many forged events as an attacker (already capable of reaching `MembershipHandler#process` with a mismatched org) can send.

### Likelihood Explanation
Given the stated precondition (a legitimate `Team` row already exists, and an attacker-controlled event asserting the same `github_id` but a different `organization.login` reaches `MembershipHandler#process`), the drift is deterministic and requires zero additional privilege beyond what's already needed to reach the handler — it falls straight out of Rails' `find_or_create_by!` semantics with no extra guard in this engine's code.

### Recommendation
In `find_or_create_team!`, always assign `team.organization = params.organization.login` (and re-run `team.github_team = params.team`) both inside and outside the creation block — e.g. `Team.find_or_create_by!(github_id: params.team.id) { |t| t.organization = params.organization.login }.tap { |t| t.update!(organization: params.organization.login) }` — or explicitly compare `team.organization` against `params.organization.login` in `process` and raise/reject on mismatch instead of silently proceeding, so cross-org membership events can never be applied without detection.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb (new or appended)
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandlerAuditTest < ActiveSupport::TestCase
        test "Team#organization does not reflect the org of a later cross-org write" do
          team = Team.create!(github_id: 999, organization: 'real-org', slug: 'devs', name: 'Devs', api_url: 'https://example.com/real-org/devs')

          payload = {
            'action' => 'added',
            'team' => { 'id' => 999, 'name' => 'Devs', 'slug' => 'devs', 'url' => 'https://example.com/real-org/devs' },
            'organization' => { 'login' => 'evil-org' },
            'member' => { 'login' => 'attacker-user' }
          }

          assert_difference -> { Membership.count }, 1 do
            MembershipHandler.call(payload)
          end

          team.reload
          # Binding under test: Team#organization should equal the org that just wrote the Membership ('evil-org')
          # but it still equals the original creator's org, proving the audit trail is stale/wrong.
          assert_equal 'real-org', team.organization
          refute_equal 'evil-org', team.organization
        end
      end
    end
  end
end
```
This directly invokes `MembershipHandler.call` (bypassing HTTP/signature layers entirely, per `Handler.call` at [6](#0-5) ) to isolate and prove the model-level audit-drift bug in `find_or_create_team!`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-24)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
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

**File:** app/models/shipit/team.rb (L1-20)
```ruby
# frozen_string_literal: true

module Shipit
  class Team < Record
    REQUIRED_HOOKS = %i[membership].freeze

    has_many :memberships
    has_many :members, class_name: :User, through: :memberships, source: :user

    has_many :github_hooks,
             -> { where(event: REQUIRED_HOOKS) },
             foreign_key: :organization,
             primary_key: :organization,
             class_name: 'GithubHook::Organization',
             inverse_of: false

    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
```
