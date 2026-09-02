### Title
Membership webhook `add_member` ignores organization ownership of the target `Team`, allowing cross-organization team-membership injection - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#process` resolves the target `Team` solely by `params.team.id` (the GitHub team's `github_id`) and never checks that `params.organization.login` in the current, correctly-signed payload matches the `organization` already persisted on that `Team` row. Because `find_or_create_team!` uses `find_or_create_by!`, the `organization` assignment inside the block only runs on the very first insert; every subsequent webhook — even one legitimately signed by a *different* organization — finds the existing row unmodified and proceeds straight to `team.add_member(member)`.

### Finding Description
The broken binding is: `params.organization.login (current signed payload) == Team#organization (persisted, decided once at creation)`. This equality is never checked anywhere in the call path.

Code path:
- `WebhooksController#verify_signature` selects the GitHub App/secret via `Shipit.github(organization: repository_owner)`, where `repository_owner` falls back to `params.dig('organization', 'login')` for events without a `repository` key (membership events). [1](#0-0) 
- This only proves the payload was signed with the secret belonging to whatever organization `organization.login` claims to be — it says nothing about the `team.id` embedded in the same payload actually belonging to that organization.
- `MembershipHandler#find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }`. [2](#0-1) 
- `find_or_create_by!` only invokes the block on INSERT; when a row with that `github_id` already exists (e.g., a privileged team synced earlier under `organization: 'shopify'`), the block is skipped and the existing, correct `organization` is returned untouched.
- `process` then unconditionally calls `team.add_member(member)` (or removes a member) with no comparison between the found team's `organization` and `params.organization.login`. [3](#0-2) 

Attacker's exact request: an attacker who legitimately controls any second organization that has its own registered GitHub webhook secret in Shipit (`github_hooks`/`GithubHook::Organization`, e.g. their own org "attacker-org") can send a `membership` event, signed with *their own* valid secret, with a fully attacker-controlled JSON body:
```json
{
  "action": "added",
  "team": { "id": <victim_privileged_team_github_id>, "name": "x", "slug": "x", "url": "https://example.com" },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-login" }
}
```
`verify_signature` passes because the signature genuinely matches `attacker-org`'s secret and `repository_owner` resolves to `attacker-org` too — the check is internally consistent but irrelevant to the `team.id` claim. `find_or_create_team!` finds the existing victim `Team` row (matched purely by `github_id`) and returns it with its real `organization` (e.g. `"shopify"`) intact. `process` then calls `team.add_member(User.find_or_create_by_login!('attacker-login'))`, adding the attacker's GitHub login as a member of the victim's privileged Shipit `Team` record.

None of the existing guards (`verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema in `params do ... end`) check cross-field consistency between `params.organization.login` and the `team.id`'s real owning organization — they only validate the shape of the payload and the authenticity of the sender for the organization the sender claims to be.

### Impact Explanation
`Shipit::Team` membership feeds `User#authorized?`, which gates access to Shipit for any deployment whose `Shipit.github_teams` restricts allowed users: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?`. [4](#0-3)  By forging a membership webhook for a `Team` they don't own, an attacker who controls any org configured in Shipit can grant themselves (or any arbitrary GitHub login) membership in a *different*, privileged `Team`, escalating into `Shipit.github_teams` authorization and thus gaining access reserved for that privileged organization's members. This is repeatable for every membership event and against any `Team` row whose `github_id` the attacker can guess or discover. This matches the High severity category ("escalation into `Shipit.github_teams` authorization").

### Likelihood Explanation
Exploitation requires the attacker to control at least one organization that already has a legitimate `GithubHook::Organization` registered with Shipit (i.e., a multi-tenant/multi-org Shipit deployment where more than one organization's webhook secret is configured), and to know or guess the numeric `github_id` of a privileged team belonging to another configured organization (team IDs are visible via the GitHub API to team members and are sequential/enumerable in many cases). No Shipit secrets, session, or API token are needed — only the ability to trigger (or directly POST, since the attacker computes their own valid HMAC with their own known secret) a `membership` webhook from their own org. This is feasible and repeatable in any Shipit install onboarding more than one GitHub organization.

### Recommendation
In `MembershipHandler#find_or_create_team!` / `#process`, verify that the found (or created) `team.organization` equals `params.organization.login` before performing `add_member`/`members.delete`, and reject (or raise) on mismatch instead of silently proceeding. Additionally, use `find_or_create_by!(github_id: params.team.id, organization: params.organization.login)` (or an explicit `team.organization == params.organization.login` guard) so a pre-existing team owned by a different organization can never be mutated by a webhook claiming a different organization.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb
test "ignores membership webhook whose organization does not own the target team" do
  privileged_team = Shipit::Team.create!(github_id: 999, organization: 'shopify', slug: 'admins', name: 'Admins', api_url: 'https://example.com')

  handler = Shipit::Webhooks::Handlers::MembershipHandler.new(
    'action' => 'added',
    'team' => { 'id' => 999, 'name' => 'Admins', 'slug' => 'admins', 'url' => 'https://example.com' },
    'organization' => { 'login' => 'attacker-org' }, # NOT the persisted 'shopify'
    'member' => { 'login' => 'attacker-login' }
  )

  assert_no_difference -> { privileged_team.reload.members.count } do
    handler.call # currently FAILS: attacker-login is added despite organization mismatch
  end
end
```
Both sides of the binding to assert: `privileged_team.organization` (`"shopify"`) vs `params.organization.login` (`"attacker-org"`) — they must be checked equal before `add_member` runs; currently they are never compared.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
