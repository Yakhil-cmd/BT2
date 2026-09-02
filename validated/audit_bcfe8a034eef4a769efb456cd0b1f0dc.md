### Title
`Team#add_member` performs no organization/tenant check before creating a `Membership` - (File: app/models/shipit/team.rb)

### Summary
`Team#add_member` is a pure in-memory/AR association append (`members.append(member) unless members.include?(member)`), with no check that `member` or `self` belong to a consistent organization. It relies entirely on its caller (`MembershipHandler#process`) to have resolved `team` and `member` correctly, and the only DB-level guard on the resulting `Membership` row is a `user_id` uniqueness scoped to `team_id` — nothing organization-related.

### Finding Description
The claimed binding is: **`team.organization` == the organization that legitimately owns `member`** must hold before `add_member` creates a `Membership`. Tracing the code:

- `Team#add_member` [1](#0-0) : only checks `members.include?(member)` for idempotency; it never reads or compares `team.organization` against anything derived from `member`.
- `Membership` model [2](#0-1) : the only validation is `validates :user_id, uniqueness: { scope: :team_id }` — no organization-consistency validation exists anywhere in the model layer.
- `MembershipHandler#process` [3](#0-2)  resolves `team` via `find_or_create_team!` (keyed by `github_id`, with `organization` only set at creation time and never re-validated) and `member` via `User.find_or_create_by_login!` (a global user lookup/creation with no org scoping), then calls `team.add_member(member)` directly.
- `Team.add_member` is therefore the last method in the write path before `Membership.create`, and it enforces nothing about provenance.

Given the stated precondition (an attacker-controlled but *signature-verified* webhook naming a colliding `team.id` and arbitrary `member.login` — established in the referenced prior questions 2 and 5), `add_member` provides no independent safety net: it will happily persist a `Membership` linking any `Team` object to any `User` object it is handed, regardless of whether the two share an organization boundary.

I could not fully verify within this pass whether `MembershipHandler#find_or_create_team!`'s `github_id`-keyed lookup and `verify_signature`'s per-organization webhook secret check (`app/controllers/shipit/webhooks_controller.rb` [4](#0-3) , `GitHubApp#verify_webhook_signature` [5](#0-4) ) actually prevent the cross-org `team.id` collision described in the precondition — that determination is scoped to questions 2/5, which this question explicitly treats as already established givens. Within the scope of *this* question — is `add_member` itself a safety net — the answer is no: it is unconditionally trusting.

### Impact Explanation
If the precondition from questions 2/5 holds (attacker can get a `Team` record with mismatched `organization` and an arbitrary `User` resolved via `find_or_create_by_login!`), `add_member` writes a `Membership` row unconditionally, joining that user to that team. Since `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) , a `Membership` row granting membership in a `Shipit.github_teams`-configured team would grant that user deploy/merge authorization across the host, matching the High severity category (escalation into `Shipit.github_teams` authorization). This confirms, at the model layer, that there is no compensating control once the team/member objects reach this point.

### Likelihood Explanation
This finding is conditioned entirely on the preconditions of the separately-scoped questions 2 and 5 (cross-org `team.id` collision via `find_or_create_team!`, and arbitrary `member.login` resolution via `find_or_create_by_login!`) actually being exploitable past `verify_signature`'s per-organization webhook secret check. This question does not itself independently establish that the attacker can reach `add_member` with mismatched org context — it only establishes that if they can, `add_member` does nothing to stop it.

### Recommendation
Add an explicit invariant check in `Team#add_member` (or in `Membership` validations) that the `member`'s known/authoritative organization membership matches `team.organization` before appending, and/or validate in `MembershipHandler#find_or_create_team!` that an existing `Team` record's `organization`/`github_id` pairing is immutable and re-verified against the webhook's `organization.login` on every event, not just at creation.

### Proof of Concept
Minitest (`test/models/team_test.rb`, in-scope for citation but the test itself would be added under `test/`):
```ruby
test "add_member creates a Membership with no organization consistency check" do
  team = shipit_teams(:test_team) # organization: "org-a"
  user = shipit_users(:walrus)    # unrelated to org-a
  refute_equal team.organization, "some-other-org-consistent-with-user" # binding does not exist to check
  team.add_member(user)
  assert Shipit::Membership.exists?(team_id: team.id, user_id: user.id)
  # No validation error raised despite team.organization having no relation to user at all
end
```
This demonstrates the equality `team.organization == <org derived from member>` is never checked before or after `add_member` runs — both sides are simply never compared. [1](#0-0) [2](#0-1)

### Citations

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
