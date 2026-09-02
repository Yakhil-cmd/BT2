### Title
`MembershipHandler#find_or_create_team!` binds a membership write to a `github_id` without verifying it belongs to the webhook-signing organization - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#process` resolves the target `Team` solely by `Team.find_or_create_by!(github_id: params.team.id)` and then calls `team.add_member(member)` (or removes a member) without ever checking that the resolved team's `organization` matches the organization whose webhook secret authenticated the request. Because `params.team.id` is attacker-controlled, an attacker who owns any org configured in Shipit can forge a `membership` webhook that references the `github_id` of a pre-existing, unrelated, privileged team and add themselves (or remove someone) from it.

### Finding Description
The binding that should hold is: `verified_organization (used in Shipit.github(organization: repository_owner) to check the HMAC signature) == team.organization (the row mutated by find_or_create_team!)`. This is never checked.

Path:
- `WebhooksController#verify_signature` picks the signing key via `Shipit.github(organization: repository_owner)`, where `repository_owner` is `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . This value comes straight from the attacker-supplied JSON body, so the attacker fully controls which org's secret is used, as long as they own that org (e.g. `evilcorp`) and thus know its webhook secret.
- Once the signature is verified against `evilcorp`'s own secret, `MembershipHandler#process` is invoked and calls `find_or_create_team!`:
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [2](#0-1) 
`find_or_create_by!` only runs the block (which sets `organization`) when a new row is created. If a `Team` row with `github_id == params.team.id` already exists — e.g. `shopify/developers` with `github_id=100` — the existing row is returned unchanged, and the block (including the `organization=` assignment) is skipped entirely.
- `process` then does `team.add_member(member)` on whatever team was returned [3](#0-2) , with no assertion that `team.organization == params.organization.login` or `== repository_owner`.
- `Team#add_member` unconditionally appends the membership [4](#0-3) .

Attacker request: a signed (with `evilcorp`'s real webhook secret) `POST /webhooks` with header `X-Github-Event: membership`, body:
```json
{
  "action": "added",
  "team": { "id": 100, "name": "x", "slug": "x", "url": "https://x" },
  "organization": { "login": "evilcorp" },
  "member": { "login": "attacker" },
  "repository": { "owner": { "login": "evilcorp" } }
}
```
Signature verification succeeds (uses `evilcorp`'s secret, which the attacker legitimately knows) via `GitHubApp#verify_webhook_signature` [5](#0-4) . `find_or_create_by!(github_id: 100)` returns the pre-existing `shopify/developers` row (`organization: 'shopify'`, per fixture) [6](#0-5) , and `team.add_member(attacker)` creates a `Membership` linking the attacker to `shopify/developers`, which is a `Shipit.github_teams` entry used for authorization elsewhere [7](#0-6) .

None of the existing guards prevent this: `verify_signature` only checks the HMAC against the org derived from the (attacker-controlled) payload field, not against the team being mutated; `drop_unhandled_event` and the `ExplicitParameters` schema in `MembershipHandler.params` only validate types/presence, not cross-field consistency; there is no `require_permission!`/organization-equality check anywhere in `find_or_create_team!` or `process`.

### Impact Explanation
A successful call grants the attacker (or removes a legitimate member) membership in an arbitrary, pre-existing `Team` row identified only by guessing/knowing its `github_id`, regardless of which organization the attacker actually controls. Since `Shipit.github_teams` is used to derive authorized users for privileged Shipit actions, this is a cross-tenant escalation into a privileged authorization team — matching "escalation into `Shipit.github_teams` authorization" (High), and depending on what that team's members are permitted to do (e.g. deploys), it can escalate to Critical-level "unauthorized deploy/rollback" if the target team gates such actions. The attack is repeatable against any `github_id` already present in the `teams` table and is not limited to a single repository — it works across the whole instance since `Team` rows are global, not scoped per stack/repo.

### Likelihood Explanation
Preconditions are modest: the attacker needs to control a GitHub organization that is configured as a Shipit GitHub App/OAuth org (so they know its `webhook_secret`), and needs to know or guess the `github_id` of a target `Team` row already present in Shipit's database (these IDs are often discoverable, e.g. via GitHub's public team/org APIs or by observing prior webhook traffic). No Shipit session, API token, or GitHub App private key is required — only the ability to sign a webhook payload with a secret the attacker legitimately possesses for their own org. This is a low-cost, fully repeatable HTTP-only attack.

### Recommendation
In `MembershipHandler#find_or_create_team!` / `#process`, enforce that the resolved team's `organization` equals the webhook's verified organization (i.e. compare `team.organization` to `params.organization.login`/`repository_owner`) before allowing any membership mutation, and raise/reject the event on mismatch rather than silently mutating the found row. Additionally, scope the `find_or_create_by!` lookup by both `github_id` and `organization` so an existing team can never be looked up cross-organization.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb (conceptual)
test "membership event cannot mutate a team belonging to another organization" do
  target_team = shipit_teams(:shopify_developers) # github_id: 1, organization: 'shopify'
  attacker = users(:attacker) # or created via login

  verified_organization = 'evilcorp'
  payload = {
    'action' => 'added',
    'team' => { 'id' => target_team.github_id, 'name' => 'x', 'slug' => 'x', 'url' => 'http://x' },
    'organization' => { 'login' => verified_organization },
    'member' => { 'login' => 'attacker' }
  }

  assert_difference -> { Shipit::Membership.count }, 0 do
    Shipit::Webhooks::Handlers::MembershipHandler.new.call(payload)
  end

  target_team.reload
  # Binding under test: verified_organization must equal target_team.organization
  refute_equal verified_organization, target_team.organization
  refute target_team.members.exists?(login: 'attacker'),
    "attacker should not be added to a Team owned by a different organization than the one that signed the webhook"
end
```
This demonstrates that, as currently implemented, `find_or_create_team!` returns the pre-existing `shopify` team and `add_member` succeeds despite `target_team.organization ('shopify') != verified_organization ('evilcorp')`, so the fix must add an explicit equality check before mutating team membership.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/fixtures/shipit/teams.yml (L3-9)
```yaml
shopify_developers:
  id: 1
  github_id: 1
  organization: shopify
  slug: developers
  name: Developers
  api_url: https://example.com/shopify/developers
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```
