### Title
Cross-organization team membership mutation via `MembershipHandler#process` 'removed' branch - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` looks up an existing `Team` by `github_id` alone, ignoring the `organization` field of the incoming payload. Because `WebhooksController#verify_signature` only checks that the request is validly signed by *some* organization's `webhook_secret` (namely the one asserted in `params['organization']['login']` or `params['repository']['owner']['login']`), an attacker who owns a GitHub organization and configures it as a Shipit webhook source can forge a `membership` event with `action: 'removed'` referencing another organization's team `github_id`, causing `team.members.delete(member)` to delete a legitimate operator's `Membership` row for a team the attacker does not own.

### Finding Description
The claimed binding is: `organization_that_signed_request == organization_that_owns_mutated_team`. Tracing the code shows this is broken.

`WebhooksController#verify_signature` resolves `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` is taken directly from the untrusted payload (`params.dig('repository','owner','login') || params.dig('organization','login')`), then verifies the signature against *that* organization's configured `webhook_secret` [1](#0-0) , [2](#0-1) . This only proves the payload was signed by whatever organization's login is embedded in the payload itself — an attacker who owns `attacker-org` and adds a Shipit webhook there can trivially satisfy this check using `attacker-org`'s own legitimate secret. It does not bind the signer to the specific `team.id`/`team.organization` referenced elsewhere in the same payload.

`MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` [3](#0-2) . Since `github_id` is a global GitHub identifier and the lookup key excludes `organization`, if a `Team` row with that `github_id` already exists (created earlier under the legitimate org), `find_or_create_by!` returns that pre-existing record — the `organization:` value from the attacker's payload is never applied to an existing record (the block only runs on creation). The handler then executes `team.members.delete(member)` [4](#0-3) , deleting the `Membership` row joining the resolved (legitimate) `Team` and the named `member`, regardless of which organization actually signed the request.

`Team` itself has no validation tying `github_id` to `organization`, and `add_member`/`members.delete` operate purely on the ActiveRecord association without any organization check [5](#0-4) . `User#authorized?` (used for `Shipit.github_teams` gating) relies on `Membership` rows, so deleting the row removes the operator's authorization the next time `authorized?` is evaluated.

**Attacker request**: `POST /webhooks` with header `X-Github-Event: membership`, signed with `attacker-org`'s own valid `webhook_secret`, body:
```json
{
  "action": "removed",
  "team": {"id": <legit_team_github_id>, "name": "...", "slug": "...", "url": "..."},
  "organization": {"login": "attacker-org"},
  "member": {"login": "<victim-operator-login>"}
}
```

No existing guard stops this: `drop_unhandled_event` only filters unsupported event types, not cross-org integrity [6](#0-5) ; `verify_signature` validates against the organization asserted in the payload itself, which the attacker controls; the `ExplicitParameters` schema in `MembershipHandler` only validates types/presence, not organization consistency [7](#0-6) .

### Impact Explanation
A single forged webhook request lets an attacker who controls an unrelated GitHub organization (with its own registered Shipit webhook secret) delete a `Membership` row for any `Team` whose numeric `github_id` they can guess or observe (team IDs are visible via GitHub's public API for many orgs, or leak through other Shipit responses). This revokes a legitimate operator's authorization on that team without their consent, denying them access to protected actions gated by `Shipit.github_teams`/`User#authorized?`. This is a cross-tenant integrity violation — one organization's signed webhook mutates another organization's authorization data — matching the Critical category ("a payload for one repository mutating another's ... team").

### Likelihood Explanation
Preconditions: the attacker must control (or register) a GitHub organization configured with a Shipit webhook and secret (a normal, low-cost, self-service action for any GitHub user who can create an org), and must know/guess the target team's GitHub numeric `id`. No Shipit credentials, session, or `Shipit.github_teams` membership are required. The request is a simple signed HTTP POST, fully repeatable against any team `github_id` the attacker can enumerate, making this feasible and repeatable at low cost.

### Recommendation
In `find_or_create_team!`, verify that `params.organization.login` matches the resolved `Team#organization` before performing the mutation (or scope the lookup by both `github_id` and `organization`, similar to `Team.find_or_create_by_handle`), and reject/no-op the event if the asserted organization doesn't own the team, mirroring the check that should also be applied to any other org-scoped webhook handlers (e.g., `TeamHandler`).

### Proof of Concept
```ruby
# minitest plan (test/models/webhooks/membership_handler_test.rb-style)
test "cross-org membership 'removed' event deletes another org's membership" do
  legit_team = shipit_teams(:some_team) # organization: "legit-org", github_id: 555
  operator = shipit_users(:walrus)
  Shipit::Membership.create!(team: legit_team, user: operator)
  assert legit_team.members.include?(operator)

  payload = {
    'action' => 'removed',
    'team' => { 'id' => legit_team.github_id, 'name' => legit_team.name, 'slug' => legit_team.slug, 'url' => legit_team.api_url },
    'organization' => { 'login' => 'attacker-org' }, # signer organization != legit_team.organization
    'member' => { 'login' => operator.login },
  }

  # signed with attacker-org's own valid webhook_secret via GithubApp.verify_webhook_signature stubbing
  Shipit::Webhooks::Handlers::MembershipHandler.call(payload)

  legit_team.reload
  refute legit_team.members.include?(operator) # BEFORE fix: fails (member removed) proving broken binding
  # binding check: assert_equal 'attacker-org', payload['organization']['login']
  # assert_not_equal 'attacker-org', legit_team.organization
end
```

### Citations

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
