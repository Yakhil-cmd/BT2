### Title
Cross-org team membership forgery via `MembershipHandler#find_or_create_team!` skips re-validating `organization` on existing teams - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` correctly ties signature verification to the org identified by `repository_owner`, and for `membership` events (which carry no `repository` key) that value is literally the same `params.dig('organization', 'login')` used by `MembershipHandler`, so the specific "repository vs organization fallback" scenario in the prompt does not produce a divergence — both fields are the same read. However, `MembershipHandler#find_or_create_team!` uses `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }`, and since `find_or_create_by!` only runs the block on **create**, any attacker who legitimately controls a webhook-secret-bearing org in a multi-tenant Shipit install can send a valid, self-signed `membership` webhook referencing an **existing** `github_id` belonging to a different org's team and add arbitrary members to it — bypassing the org binding entirely for pre-existing teams.

### Finding Description
The claimed binding is: `repository_owner` (used by `verify_signature` at [1](#0-0)  to pick the webhook secret) `==` `params.organization.login` (used by `MembershipHandler#find_or_create_team!` to set `team.organization`, at [2](#0-1) ).

For `membership` events GitHub never includes a `repository` key, so `repository_owner` reduces to the same `params.dig('organization','login')` dig call — meaning per-request the two values are trivially identical, and the "fake `repository.owner.login`" fallback-order exploit described in the prompt cannot desynchronize them: if an attacker supplies a `repository.owner.login` naming a victim org, `Shipit.github(organization: repository_owner)` will select the victim's secret, and the attacker (who does not have that secret) will fail `verify_webhook_signature` and get `422`, exactly as the prompt itself concedes. So that specific claimed bypass is not exploitable, confirmed by `verify_webhook_signature` at [3](#0-2) .

The real defect is elsewhere in the same handler: `Team.find_or_create_by!(github_id: params.team.id)` at [4](#0-3)  only executes the block (which sets `team.organization = params.organization.login`) when a **new** record is created; when a row with that `github_id` already exists, ActiveRecord's `find_or_create_by!` simply returns the found record untouched, and no code anywhere checks that the found team's pre-existing `organization` column matches the org that produced a valid signature for this request. `Team#add_member` at [5](#0-4)  then unconditionally appends the member.

Exploit flow: Shipit hosts multiple orgs (e.g. `attacker-org` and `victim-org`), each with its own `webhook_secret` (standard multi-tenant config, `Shipit.github(organization:)`). The attacker legitimately controls `attacker-org` and can sign webhooks with its secret. They send a `membership` `action: 'added'` webhook, correctly signed for `attacker-org`, with `organization.login: 'attacker-org'` (so `repository_owner == organization.login == 'attacker-org'`, passing `verify_signature`), but `team.id` set to the numeric GitHub `github_id` of a **pre-existing** `Team` row that actually belongs to `victim-org` (e.g. a team already onboarded via `Shipit.github_teams`/`Team.find_or_create_by_handle`, see `lib/shipit.rb:256-258`), and `member.login` set to an arbitrary GitHub login (their own account). `MembershipHandler#process` at [6](#0-5)  finds the existing victim team (skipping the organization-setting block), resolves/creates the target user via `User.find_or_create_by_login!`, and calls `team.add_member(member)` — adding the attacker-chosen user to a team they were never actually granted by GitHub.

This matters because `User#authorized?` at [7](#0-6)  grants full Shipit access purely based on `teams.where(id: Shipit.github_teams.map(&:id)).exists?` — it does not re-check GitHub team membership live, nor does it care which org's webhook secret produced the row. If the targeted `github_id` corresponds to one of the `Team` records in `Shipit.github_teams`, this webhook forgery becomes a full authentication/authorization bypass: an unprivileged attacker turns an arbitrary GitHub account into a fully authorized Shipit user.

Existing guards do not catch this: `verify_signature` only proves the request was signed by *an* onboarded org, not that the org matches the target team's owner; the `ExplicitParameters` schema on `MembershipHandler` (`params do ... end`, [8](#0-7)  ) only validates types/presence, not cross-field consistency; and no model validation on `Team` ties `organization` to `github_id` uniqueness enforcement against tampering.

### Impact Explanation
An attacker who controls any single onboarded org's webhook secret (i.e., is a legitimate admin of one tenant org in a multi-org Shipit deployment) can forge `membership` webhooks that add arbitrary GitHub accounts to **any pre-existing** `Team` row in the Shipit database, regardless of which org actually owns that team, as long as they know/guess the team's numeric GitHub `github_id`. If that team is one of the ones configured in `Shipit.github_teams` (the application's authorization gate, `lib/shipit.rb:256-258`), this results in unauthenticated/unauthorized users being granted full application access — matching the "High - escalation into `Shipit.github_teams` authorization" category. It is repeatable against any team whose `github_id` the attacker can determine, and the blast radius spans every tenant org hosted on the same Shipit instance, not just the attacker's own.

### Likelihood Explanation
Preconditions: (1) Shipit configured with multiple GitHub orgs, each with its own onboarded `webhook_secret`; (2) attacker legitimately controls at least one such onboarded org (a realistic scenario in shared/multi-tenant Shipit deployments); (3) attacker knows or can enumerate the numeric `github_id` of a target team belonging to another org (GitHub team IDs are simple integers and can often be discovered via the GitHub API/UI for teams the attacker can see, or guessed/brute-forced since they are sequential). Attacker cost is a single crafted, self-signed HTTP POST to `/webhooks`; no Shipit session or secrets from the victim org are needed. The attack is fully repeatable and requires no live GitHub interaction for the PoC.

### Recommendation
In `MembershipHandler#find_or_create_team!`, always assign/validate `team.organization` against `params.organization.login`, and reject (raise) if an existing team's `organization` does not match the organization that verified the current webhook's signature (i.e., `repository_owner` from the controller). At minimum, run the assignment outside the `find_or_create_by!` block unconditionally, then explicitly compare `team.organization` to the verified org and abort processing (e.g., raise/`head 422`) on mismatch before calling `team.add_member`/`team.members.delete`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb (proof sketch)
test "membership handler does not re-validate organization for a pre-existing team" do
  victim_team = Shipit::Team.create!(
    github_id: 999,
    organization: 'victim-org',
    name: 'Victim Team',
    slug: 'victim-team',
    api_url: 'https://example.com/victim'
  )

  params = {
    'action' => 'added',
    'team' => { 'id' => 999, 'name' => 'Victim Team', 'slug' => 'victim-team', 'url' => 'https://example.com/victim' },
    'organization' => { 'login' => 'attacker-org' }, # attacker's own, verified org
    'member' => { 'login' => 'attacker-controlled-user' },
  }

  assert_no_difference -> { Shipit::Team.count } do
    Shipit::Webhooks::Handlers::MembershipHandler.new.call(params)
  end

  victim_team.reload
  # BROKEN BINDING: organization column is untouched (still 'victim-org'),
  # yet the attacker-chosen member was added to a team they don't own.
  assert_equal 'victim-org', victim_team.organization
  assert_includes victim_team.members.map(&:login), 'attacker-controlled-user'
end
```
This demonstrates: signature verification org (`attacker-org`) diverges from the team's actual `organization` (`victim-org`) with no cross-check, letting one tenant's verified webhook mutate another tenant's `Team#members`.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
