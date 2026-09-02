### Title
Cross-organization team membership write via `MembershipHandler#process` matching Team by `github_id` without verifying `organization` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#process` never checks that `params.organization.login` equals the `organization` of the `Team` row resolved by `find_or_create_team!`. Because `Team.find_or_create_by!` keys strictly on `github_id` (globally unique on GitHub, not scoped by org in Shipit's schema/lookup), a signed `membership` webhook from org A referencing a team whose `github_id` already belongs to an existing `Team` row for privileged org B will locate and mutate org B's team instead of creating/using a team for org A.

### Finding Description
The broken binding is: `params.organization.login == team.organization` for the `Team` row returned by `find_or_create_team!`. This equality is never asserted anywhere in `MembershipHandler#process` [1](#0-0)  nor inside `find_or_create_team!` itself [2](#0-1) .

`find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login; ... }`. The block that assigns `organization` (and `github_team=`) only runs on the **create** path of `find_or_create_by!`; if a `Team` row with that `github_id` already exists (e.g., previously synced for org B, a privileged org referenced in `Shipit.github_teams` via `Shipit.github_teams` -> `Team.find_or_create_by_handle` [3](#0-2) ), the existing row for org B is returned unchanged, completely ignoring `params.organization.login`.

`WebhooksController#verify_signature` only checks the HMAC signature against the webhook secret configured for `repository_owner` (which for a `membership` event payload falls back to `params.dig('organization','login')`) [4](#0-3) [5](#0-4) . It authenticates *that the payload really came from org A's webhook*, it does not, and cannot, ensure that the `team` object embedded in the payload actually belongs to org A — that's an application-level invariant the handler must enforce itself, and it does not.

Attack flow:
1. Attacker controls org A, which is onboarded to Shipit with its own `webhook_secret` (a legitimately signed channel per the threat model).
2. Attacker knows or guesses the numeric GitHub `team.id` (`github_id`) of a team belonging to privileged org B that is already present in `Shipit.github_teams`/has a `Team` row (e.g. because it was already synced through normal operation, `refresh_members!`, or a prior legitimate `membership`/`team` webhook for org B).
3. Attacker POSTs a `membership` webhook to `/webhooks`, signed with org A's `webhook_secret`, with `organization.login = "A"`, `action = "added"`, `team.id = <org B's github_id>`, `member.login = <attacker-controlled login>`.
4. `verify_signature` succeeds (correctly signed by org A's secret for org A).
5. `MembershipHandler#process` calls `find_or_create_team!`, which finds the pre-existing `Team` row for org B by `github_id`, ignoring that `organization.login` is `"A"`.
6. `team.add_member(member)` appends the attacker-controlled `member` (created via `User.find_or_create_by_login!`) to org B's team's `memberships` [6](#0-5) .
7. If that team is one of `Shipit.github_teams`, the injected member now satisfies `User#authorized?` (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`) [7](#0-6) , granting them Shipit-wide privileged authorization without ever being a real member of org B.

No control in `ExplicitParameters` schema, `drop_unhandled_event`, or `verify_signature` cross-checks org identity against the embedded team payload, so the divergence is never caught.

### Impact Explanation
An attacker who only controls their own onboarded org (org A) can grant an arbitrary attacker-chosen GitHub login membership in a `Team` row tied to a different, privileged organization (org B) that is part of `Shipit.github_teams`. If that team is used for authorization (`User#authorized?`), this is escalation into `Shipit.github_teams` authorization — a cross-tenant privilege escalation, matching the "High: escalation into `Shipit.github_teams` authorization" impact category. It is repeatable against any `github_id` the attacker can enumerate/guess for any team that Shipit already has a `Team` row for, across arbitrary organizations, as many times as desired.

### Likelihood Explanation
Preconditions: attacker's own organization (A) must be a legitimate Shipit-connected GitHub organization (so they control a valid `webhook_secret` for a `membership` event channel), and a `Team` row for the target org B's team (with the target `github_id`) must already exist in Shipit's database (typical once Shipit has synced `Shipit.github_teams` for its primary/privileged org). GitHub team IDs are sequential/enumerable integers, making them guessable/discoverable (e.g., via a public API or by observing other webhooks). Attacker cost is a single crafted HTTP POST with a valid HMAC signed with their own known secret — no privileged credentials of org B or Shipit needed. This is fully repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!` (and analogous handlers, e.g. `TeamHandler` if it exists), verify that any existing `Team` row found by `github_id` has `organization == params.organization.login` before proceeding; if it doesn't match, raise/reject rather than mutate. Alternatively, scope the lookup by both `github_id` and `organization`, and treat a `github_id` collision across organizations as an error condition (since GitHub team IDs are globally unique, a mismatch indicates either a renamed org or an attack, and should never be silently accepted).

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/membership_handler_test.rb` would be the natural location, but per rules referencing `test/**` structure is illustrative only):

1. Create `team_b = Shipit::Team.create!(github_id: 999, organization: 'org-b', slug: 'privileged-team', name: 'Privileged', api_url: 'https://api.github.com/teams/999')`.
2. Add `team_b` to the set considered by `Shipit.github_teams` (stub `Shipit.github_teams` to return `[team_b]`).
3. Build a `membership` webhook payload: `{ action: 'added', team: { id: 999, name: 'Privileged', slug: 'privileged-team', url: '...' }, organization: { login: 'org-a' }, member: { login: 'attacker' } }`.
4. Invoke `Shipit::Webhooks::Handlers::MembershipHandler.new.call(payload)` (bypassing HTTP-layer signature verification, since that is out of scope of the handler-level bug and assumed to already have passed per the threat model).
5. Assert `Shipit::Team.find_by(github_id: 999).organization == 'org-b'` (unchanged) while `payload['organization']['login'] == 'org-a'` — i.e. explicitly assert `refute_equal params.organization.login, team.organization` to prove the mismatch is never checked.
6. Assert `Shipit::User.find_by(login: 'attacker').teams.include?(team_b)` is `true` — proving `add_member` succeeded despite the org mismatch.
7. Assert `Shipit::User.find_by(login: 'attacker').authorized?` is `true` — proving the cross-org write yields privileged Shipit authorization. [8](#0-7)

### Citations

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-47)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandler < Handler
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
      end
    end
  end
end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
