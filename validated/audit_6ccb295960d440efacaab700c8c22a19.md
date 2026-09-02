### Title
Cross-tenant team membership injection via `MembershipHandler#find_or_create_team!` ignoring `organization` on existing records - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` resolves an existing `Team` solely by `github_id`, never checking that the webhook's `organization.login` matches the team's stored `organization`. An attacker who can get a validly-signed `membership` webhook accepted for *their own* organization can target any pre-existing `Team` row (including one listed in `Shipit.github_teams`) by supplying that team's `github_id`, causing themselves to be added as a `Membership`.

### Finding Description
The broken binding: the organization that signs/authenticates the webhook (checked in `verify_signature`) must equal the organization that owns the `Team` row being mutated — but the code never enforces `params.organization.login == team.organization`.

`WebhooksController#verify_signature` derives `repository_owner` from `params.dig('organization', 'login')` for events with no `repository` key (membership events), then verifies the signature using `Shipit.github(organization: repository_owner)`. This only proves the payload was signed by *whatever org's* config the attacker's `organization.login` maps to — nothing about which `Team` row is targeted. [1](#0-0) [2](#0-1) 

`MembershipHandler#find_or_create_team!` then does:
```ruby
Team.find_or_create_by!(github_id: params.team.id) do |team|
  team.github_team = params.team
  team.organization = params.organization.login
end
```
The `organization` assignment only executes inside the `create` block. If a `Team` with that `github_id` already exists (e.g. a real, victim-owned team already present in `Shipit.github_teams` via `Shipit.github_teams` → `Team.find_or_create_by_handle`), the lookup short-circuits and returns the existing row — completely ignoring `params.organization.login`. [3](#0-2) [4](#0-3) [5](#0-4) 

`process` then does `member = User.find_or_create_by_login!(params.member.login)` and `team.add_member(member)`, inserting a `Membership` row regardless of the organization mismatch. [6](#0-5) [7](#0-6) 

`User#authorized?` checks membership against `Shipit.github_teams.map(&:id)`, so an attacker with a `Membership` on any team in that list becomes fully authorized: [8](#0-7) 

Exploit flow (given the stated precondition — attacker's own org has a distinct, valid webhook config/secret on this Shipit instance, a scenario only meaningful in multi-tenant `secrets.github` deployments where `Shipit.github_app_config(organization)` looks up per-org secrets): [9](#0-8) 
1. Attacker POSTs a `membership` event, `X-Github-Event: membership`, signed with their own org's `webhook_secret`.
2. Payload: `action: "added"`, `team.id: <victim team's github_id>`, `organization.login: "attacker-org"`, `member.login: "attacker"`.
3. `verify_signature` passes because it only checks the signature against the attacker's own org config.
4. `find_or_create_team!` resolves the pre-existing victim `Team` by `github_id` alone.
5. `team.add_member(User.find_or_create_by_login!("attacker"))` creates the `Membership`.
6. `attacker.authorized?` now returns `true` via `Shipit.github_teams.map(&:id)`.

No existing guard prevents this: `verify_signature` only authenticates *a* signer, not *the* signer for the targeted team's organization; `find_or_create_team!` has no read/compare of the team's stored `organization` on the existing-row path; there is no model validation tying `Team#organization` to `Membership` creation.

### Impact Explanation
A `Membership` row is written for a `Team` the attacker does not own, and `User#authorized?` flips to `true` for the attacker's Shipit account, granting instance-wide authorization (this matches the "escalation into `Shipit.github_teams` authorization" category). This is repeatable against any `Team.github_id` the attacker can learn (team IDs are often discoverable via GitHub's API/UI) and is not scoped to a single stack/repository — it grants global authorization on the Shipit instance, not just for one tenant.

### Likelihood Explanation
Requires a multi-tenant Shipit deployment where `secrets.github` (`github_default_organization` non-nil) maps multiple organizations to independent webhook secrets, and where the attacker legitimately controls/administers one of those configured orgs (as stipulated in the question). Under that precondition, the attack costs a single crafted HTTP POST with a correctly-computed HMAC using the attacker's own legitimate secret — no other credentials or privileges are needed, and it is fully repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, require an explicit match between `params.organization.login` and the resolved `Team#organization` (or scope the `find_or_create_by!` lookup to `github_id: ..., organization: params.organization.login`), rejecting/aborting processing when an existing team's `organization` doesn't match the payload's `organization.login`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "membership event cannot add attacker to a team owned by a different organization" do
  victim_team = shipit_teams(:shopify_developers) # organization: "shopify", github_id: X

  GithubHook::Organization.create!(organization: 'attacker-org', webhook_secret: 'attacker-secret')
  # (assumes multi-org secrets.github config maps 'attacker-org' -> webhook_secret 'attacker-secret')

  payload = {
    action: 'added',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker' }
  }.to_json

  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', payload)

  assert_no_difference -> { Shipit::Membership.count }, "attacker should not be added to victim's team" do
    post shipit.github_webhooks_path,
      params: payload,
      headers: { 'X-Github-Event' => 'membership', 'X-Hub-Signature' => signature, 'Content-Type' => 'application/json' }
  end

  attacker = Shipit::User.find_by(login: 'attacker')
  refute attacker&.authorized?, "attacker must not become authorized via cross-org membership webhook"
end
```
Current code fails this test: the `Membership` is created and `authorized?` becomes `true`, confirming the vulnerability.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
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

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/models/shipit/team.rb (L17-21)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
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
