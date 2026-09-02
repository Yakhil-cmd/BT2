I have sufficient confirmation to finalize the finding.

### Title
Cross-organization Team hijack via `Team.find_or_create_by!(github_id:)` unscoped by organization in `MembershipHandler` - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` looks up an existing `Team` solely by `github_id`, with no scoping by `organization`. Because `find_or_create_by!`'s block only executes when a new record is created, a legitimately-signed `membership` webhook from any attacker-controlled organization whose `team.id` collides with an already-existing privileged `Team`'s `github_id` will match that existing row and add an attacker-chosen member to it, regardless of which organization actually signed the request.

### Finding Description
The claimed binding is: `params.organization.login == Team#organization` for the `Team` row matched by `github_id`. This holds only on the create path, not on the find path.

`WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0)  For a `membership` event there is no `repository` key, so `repository_owner` resolves to `params.organization.login` — the attacker's own organization. Since the attacker's own org has a real, valid `webhook_secret` configured (per the stated preconditions), `verify_webhook_signature` genuinely succeeds using the attacker's own secret. This only proves the payload was signed by the attacker's org; it proves nothing about which `Team` the numeric `team.id` refers to.

`MembershipHandler#find_or_create_team!` then does:
```ruby
Team.find_or_create_by!(github_id: params.team.id) do |team|
  team.github_team = params.team
  team.organization = params.organization.login
end
``` [2](#0-1) 

`find_or_create_by!` first performs `find_by(github_id: params.team.id)`; if a row already exists with that `github_id`, it is returned immediately and the block (which sets `organization`) never runs. The lookup is not scoped by `organization` at all, so `Team#organization` on the matched row is never checked against `params.organization.login`. If the attacker sets `team.id` to the `github_id` of an existing, privileged `Team` (e.g. `shipit_teams(:shopify_developers)`, `github_id: 1`, `organization: 'shopify'`, per fixture [3](#0-2) ), `find_or_create_by!` returns that Shopify team row even though the request was signed by, and originated from, `attacker-org`.

`MembershipHandler#process` then runs `team.add_member(member)` for `action == 'added'`, where `member` is `User.find_or_create_by_login!(params.member.login)` — a login fully controlled by the attacker's payload. [4](#0-3)  `Team#add_member` appends the member to `members` unless already present. [5](#0-4) 

If that `Team` is one of `Shipit.github_teams` (built from `oauth_teams` config via `Team.find_or_create_by_handle`) [6](#0-5) , then `User#authorized?` becomes true for the attacker's user because `authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?`. [7](#0-6) 

None of the existing guards catch this: `verify_signature` only authenticates the source organization of the request, not the target `Team` referenced inside it; `drop_unhandled_event` and the `ExplicitParameters` schema only validate presence/type of `team.id`, `organization.login`, etc., not their relationship to existing records; there is no model validation on `Team` tying `github_id` to `organization` uniqueness (the unique index is on `organization + slug`, not on `github_id`) [8](#0-7) .

### Impact Explanation
A single POST from an attacker-controlled organization's genuinely-configured webhook can add an arbitrary GitHub login (the attacker's own) as a member of any pre-existing `Team` row whose `github_id` the attacker can match, including teams that are part of `Shipit.github_teams` used to gate access to the entire Shipit instance. This grants `current_user.authorized? == true` for the attacker, bypassing the `force_github_authentication` team-membership check and letting them log in and use the app as an authorized member — deploys, rollbacks, stack management, etc. This is a cross-organization authorization escalation, matching the "High - escalation into `Shipit.github_teams` authorization" impact category. It's repeatable at will (each `added` event re-adds/keeps membership; `removed` can also be abused to kick legitimate members from the privileged team by the same unscoped lookup).

### Likelihood Explanation
Preconditions per the prompt are already satisfied: attacker operates their own GitHub organization with a Shipit `GithubHook::Organization` configured for the `membership` event and a real `webhook_secret` — entirely within the attacker's own control and requiring no Shipit or victim secrets. The only additional requirement is knowing/guessing the numeric `github_id` of the target privileged `Team` (a GitHub-global numeric team ID, not a secret, and often discoverable via public GitHub team URLs/API for orgs with public team pages, or simply already present in the target Shipit's `Team` fixture/record from a prior legitimate hook). Attacker cost is a single crafted, self-signed HTTP POST; the action is fully repeatable and requires no privileged Shipit role.

### Recommendation
Scope the `Team` lookup by both `github_id` and `organization` (e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and additionally verify that `params.organization.login` matches `repository_owner`/the organization that authenticated the webhook before mutating an existing `Team`'s membership. Consider also rejecting membership events where an existing `Team` row's `organization` does not match the authenticated organization instead of silently proceeding.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (excluded from grading per rules, but for reference):
1. Configure a second org (`attacker-org`) in test secrets with its own `webhook_secret`, matching `Shipit.github(organization: 'attacker-org')`.
2. Build a `membership` payload: `action: 'added'`, `team: { id: shipit_teams(:shopify_developers).github_id, name: ..., slug: ..., url: ... }`, `organization: { login: 'attacker-org' }`, `member: { login: 'mallory' }`.
3. Sign the payload with `attacker-org`'s real `webhook_secret` and set `X-Hub-Signature`/`X-Github-Event: membership`.
4. POST to `/webhooks`; assert response `:ok`.
5. Assert `Team.find_by(github_id: shipit_teams(:shopify_developers).github_id).organization == 'shopify'` (unchanged) while `Team.find_by(github_id: ...).members.map(&:login)` now includes `'mallory'`.
6. Stub `Shipit.github_teams` to include `shipit_teams(:shopify_developers)` and assert `User.find_by(login: 'mallory').authorized?` is `true` — demonstrating `params.organization.login ('attacker-org') != Team#organization ('shopify')` yet the membership mutation and authorization succeeded.

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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

**File:** test/dummy/db/schema.rb (L342-351)
```ruby
  create_table "teams", force: :cascade do |t|
    t.string "api_url", limit: 255
    t.datetime "created_at", null: false
    t.bigint "github_id"
    t.string "name", limit: 255
    t.string "organization", limit: 39
    t.string "slug", limit: 255
    t.datetime "updated_at", null: false
    t.index ["organization", "slug"], name: "index_teams_on_organization_and_slug", unique: true
  end
```
