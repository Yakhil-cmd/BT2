### Title
Cross-organization team membership forgery via `find_or_create_team!` missing organization re-validation - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` only sets `team.organization = params.organization.login` inside the `find_or_create_by!` block, which ActiveRecord only executes on record initialization (creation), never on the "find" branch [1](#0-0) . Once a `Team` row exists for a given `github_id`, any subsequent `membership` webhook — signed with the credentials of a *different, unrelated organization* that is a legitimate tenant of the same shared Shipit instance — can reuse that `github_id` and mutate the existing team's membership, because `process` calls `team.add_member(member)` / `team.members.delete(member)` unconditionally, without ever checking that the webhook's authenticated organization matches `team.organization` [2](#0-1) .

### Finding Description
The broken binding is: `verified_webhook_organization == team.organization` must hold before `team.add_member`/`team.members.delete` executes. The code enforces no such equality on the "team already exists" path.

Trace:
- `WebhooksController#verify_signature` authenticates the payload only against the organization derived from `repository_owner` (`params.dig('repository','owner','login') || params.dig('organization','login')`), using `Shipit.github(organization: repository_owner).verify_webhook_signature` [3](#0-2) . This proves the request came from *some* organization onboarded on this Shipit instance (`repository_owner`), but says nothing about which `team.id`/`github_id` that organization is entitled to touch.
- `MembershipHandler#process` calls `find_or_create_team!` then unconditionally does `team.add_member(member)` for `action == 'added'` [2](#0-1) .
- `find_or_create_team!` uses `Team.find_or_create_by!(github_id: params.team.id) { |team| ...; team.organization = params.organization.login }` [1](#0-0) . Per ActiveRecord semantics, the block only runs when a new record is being built (i.e., on create); if `Team.find_by(github_id:)` already returns a row, the block is skipped entirely and `team.organization` retains its original value.
- `Team#add_member` and `members.delete` perform no organization check either [4](#0-3) .

Exploit flow: A legitimate org ("realorg") performs its first membership sync, creating `Team#github_id = X, organization = 'realorg'` (e.g. seeded as `shipit_teams(:shopify_developers)`, matching test fixture `team_params` with `id: shipit_teams(:shopify_developers).id`) [5](#0-4) . An attacker who administers their own onboarded GitHub organization ("attacker-org") on the same shared Shipit instance sends a `membership` webhook, correctly signed with `attacker-org`'s own webhook secret, containing `team: { id: X, ... }`, `organization: { login: 'attacker-org' }`, `member: { login: 'attacker' }`, `action: 'added'`. `verify_signature` passes (it only authenticates that the sender is `attacker-org`) [6](#0-5) . `find_or_create_team!` finds the existing `realorg` team row by `github_id: X` and skips the block, leaving `team.organization == 'realorg'` [1](#0-0) . `team.add_member(attacker_user)` then runs regardless, adding the attacker to `realorg`'s team [7](#0-6) .

No existing guard closes this gap: `drop_unhandled_event` only checks the event type exists a handler [8](#0-7) ; the `ExplicitParameters` schema only validates types/presence, not cross-field consistency [9](#0-8) ; `verify_signature` authenticates the sending org but never the `team.id` ownership.

### Impact Explanation
This lets a webhook correctly signed by any onboarded organization ("attacker-org") mutate team membership data belonging to a different organization ("realorg") purely by guessing/observing the target's numeric GitHub team `id` (discoverable via GitHub's public team API/URLs). Since `User#authorized?` is computed from `teams.where(id: Shipit.github_teams.map(&:id))` [10](#0-9) , if the targeted team is one of the teams configured in `Shipit.github_teams`, the attacker-controlled GitHub login becomes an authorized Shipit user — a direct escalation into `Shipit.github_teams` authorization / cross-tenant record write, matching the Critical "payload for one repository mutating another's stack, commit, task or team" / authentication-bypass category. The attack is repeatable against any team `github_id` known to the attacker, across any number of pre-existing teams.

### Likelihood Explanation
Preconditions: (1) the target team's `Team` row must already exist (satisfied the first time any org syncs membership, e.g. via `bin/rake teams:fetch` or an earlier legitimate `membership` webhook — very common in a live deployment); (2) the attacker must administer or control at least one GitHub organization that is legitimately onboarded to the same shared Shipit instance (has a valid webhook secret configured), which is realistic for any multi-tenant/self-hosted Shipit deployment serving multiple orgs; (3) the attacker must know/guess the target team's `github_id`, which is a small integer exposed by GitHub's team API/URLs. Attacker cost is low — a single signed HTTP POST to `/webhooks` — and the action is fully repeatable.

### Recommendation
In `find_or_create_team!`, always assert `team.organization == params.organization.login` after find-or-create (raise/reject the event on mismatch), rather than only setting it in the creation block. E.g.:
```ruby
def find_or_create_team!
  team = Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
  raise ArgumentError, "team/organization mismatch" unless team.organization == params.organization.login
  team
end
```
Alternatively, look the team up scoped by `(github_id, organization)` instead of `github_id` alone.

### Proof of Concept
In `test/models/webhooks/handlers/membership_handler_test.rb` (or via `Shipit::WebhooksController`):
```ruby
test "membership handler does not let a different org mutate an existing team's members" do
  team = shipit_teams(:shopify_developers) # organization == 'shopify', pre-existing
  params = {
    action: 'added',
    team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
    organization: { login: 'attacker-org' }, # simulated cross-org webhook, correctly signed for attacker-org
    member: { login: 'attacker' }
  }

  assert_no_difference -> { team.reload.members.count } do
    Shipit::Webhooks::Handlers::MembershipHandler.call(params.deep_stringify_keys)
  end

  assert_equal 'shopify', team.reload.organization # binding: organization must remain 'shopify'
  assert_not_includes team.members.map(&:login), 'attacker'
end
```
Before the fix, this test fails: `team.organization` stays `'shopify'` but `team.members` gains `'attacker'` anyway, proving the missing equality check `verified_webhook_organization == team.organization` before `add_member`.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L208-214)
```ruby
    def membership_params
      { action: 'added', team: team_params, organization: { login: 'shopify' }, member: { login: 'walrus' } }.merge(repository_params)
    end

    def team_params
      { id: shipit_teams(:shopify_developers).id, slug: 'developers', name: 'Developers', url: 'http://example.com' }
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
