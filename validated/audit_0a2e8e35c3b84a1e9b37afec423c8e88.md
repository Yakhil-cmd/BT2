### Title
Cross-organization Team hijack via `github_id` collision in `MembershipHandler#find_or_create_team!` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` looks up a `Shipit::Team` solely by `github_id`, an attacker-choosable integer in the webhook payload, without ever verifying that `params.organization.login` matches the `organization` already stored on that team. Because `WebhooksController#verify_signature` authenticates the request only against the attacker's own organization (via `repository_owner`/`organization.login`), an attacker who owns any GitHub org/App can send a `membership` webhook whose `team.id` collides with a pre-existing privileged team's `github_id`, causing `team.add_member(member)` to add an attacker-controlled GitHub login to that pre-existing (foreign) team.

### Finding Description
The broken binding is: `Team#organization` (persisted value, e.g. `'shopify'`) must equal `params.organization.login` (the org whose `webhook_secret` verified the request, e.g. `'attacker-org'`). No code enforces this equality.

Path: `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature`, which resolves `Shipit.github(organization: repository_owner)` from `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) [2](#0-1) . This only proves the request was signed with the attacker's *own* org's `webhook_secret` (which the attacker legitimately possesses since it's their org's GitHub App). It says nothing about `team.id`.

`MembershipHandler#process` then calls `find_or_create_team!`, which does:
```ruby
Team.find_or_create_by!(github_id: params.team.id) do |team|
  team.github_team = params.team
  team.organization = params.organization.login
end
``` [3](#0-2) 

`find_or_create_by!` first performs `find_by(github_id: params.team.id)`; if a row exists, it is returned immediately and the block (which would set/overwrite `organization`) never runs — this is standard ActiveRecord semantics, not a workaround. If the attacker crafts a `team.id` numerically equal to an existing, privileged team's `github_id` (team IDs are attacker-visible/guessable global GitHub integers, not scoped to an org), the pre-existing team row (belonging to `'shopify'`) is returned, then `process` calls `team.add_member(member)` where `member` is `User.find_or_create_by_login!(params.member.login)` — a login fully controlled by the attacker's payload [4](#0-3) . `add_member` unconditionally appends the member to `members` [5](#0-4) .

No guard exists: `verify_signature` never compares `params.organization.login` to any value fetched from the `Team` row, `find_or_create_by!` doesn't scope by `organization`, and there is no `require_permission!`/ownership check between the authenticating org and the target team in this handler.

### Impact Explanation
An attacker who controls only their own GitHub org/App (and thus its `webhook_secret`) can add an arbitrary attacker-chosen GitHub login as a member of a team belonging to a *different, unrelated organization* already known to Shipit — without ever authenticating as that organization. If that target team is listed in `Shipit.github_teams` (the set of teams whose membership grants `User#authorized?`) [6](#0-5) , this becomes escalation into Shipit's authorization gate: the attacker's own GitHub login becomes a member of a `Shipit.github_teams` team, and any user logging in with that GitHub identity is treated as `authorized?`. This is repeatable per organization/team-id collision and crosses tenant boundaries (a payload authenticated for org A mutates a team scoped to org B), matching the High severity category ("escalation into `Shipit.github_teams` authorization").

### Likelihood Explanation
Preconditions: (1) the attacker must operate/own a GitHub organization or App capable of emitting a signed `membership` webhook to the Shipit host (achievable by any GitHub user who can create an org and install a GitHub App pointing its webhook at the target Shipit instance, or otherwise cause a `membership` event with a crafted `X-Hub-Signature` derived from their own org's `webhook_secret`); (2) knowledge or brute-forcing of a `github_id` that collides with an existing privileged `Team` row — GitHub team IDs are sequential/enumerable integers and Shipit team IDs are often discoverable via the app's own UI/API or GitHub's public team listing endpoints for orgs with public teams, lowering the cost significantly. No Shipit secrets, sessions, or `github_teams` membership are required. This is fully repeatable and requires no privileged role.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization`, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and additionally verify on every invocation (not only creation) that `team.organization == params.organization.login`, raising/dropping the event otherwise. More generally, `verify_signature` should ensure the authenticated organization matches the organization of any record being mutated by the payload, not just the record used to pick the GithubApp secret.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb
test "membership webhook cannot hijack a team belonging to a different organization" do
  privileged_team = Shipit::Team.create!(
    github_id: 424242,
    organization: 'shopify',
    name: 'core',
    slug: 'core',
    api_url: 'https://api.github.com/teams/424242'
  )

  payload = {
    'action' => 'added',
    'team' => { 'id' => 424242, 'name' => 'core', 'slug' => 'core', 'url' => 'https://api.github.com/teams/424242' },
    'organization' => { 'login' => 'attacker-org' }, # attacker's own org, verified via attacker's webhook_secret
    'member' => { 'login' => 'attacker-controlled-login' }
  }

  Shipit::Webhooks::Handlers::MembershipHandler.new(payload).process

  privileged_team.reload
  # Binding check: organization stored on the returned team is untouched (still 'shopify'),
  # even though the request was authenticated as 'attacker-org'.
  assert_equal 'shopify', privileged_team.organization
  refute_equal 'attacker-org', privileged_team.organization

  # Impact: attacker's login was added as a member of the privileged, foreign-org team.
  assert privileged_team.members.exists?(login: 'attacker-controlled-login')
end
```
This demonstrates that `find_or_create_by!` matched purely on `github_id`, skipped the creation block (organization never set/compared), and the attacker's payload — authenticated only for `attacker-org` — successfully mutated membership of a team scoped to `shopify`.

### Citations

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
