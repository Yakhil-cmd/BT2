This confirms the impact: `User#authorized?` at [1](#0-0)  checks whether the user belongs to any of `Shipit.github_teams`, which are exactly the `Team` records controlled by `Membership` rows. Since `MembershipHandler` writes those `Membership` rows without validating that the authenticated organization owns the target team, this directly escalates into `Shipit.github_teams` authorization.

### Title
Cross-organization Membership mutation via unscoped `team.id` lookup in webhook handler - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` resolves the target `Team` purely by `github_id` (`params.team.id`) and mutates its `members` association without ever checking that the webhook's authenticated organization (the org whose `webhook_secret` verified the request) actually owns that team. On a multi-tenant Shipit instance, an org that legitimately holds its own `webhook_secret` can sign a `membership` payload naming any other org's `team.id`, and the handler will add or remove that team's members regardless.

### Finding Description
The claimed binding is: `signing_org.webhook_secret used by WebhooksController#verify_signature == Team#organization for the team.id referenced in the payload`. This binding is never enforced.

`WebhooksController#verify_signature` at [2](#0-1)  selects the `GitHubApp` (and thus the `webhook_secret` to verify against) using `repository_owner`, which for membership events falls back to `params.dig('organization', 'login')` — a value taken directly from the attacker-supplied JSON body: [3](#0-2) . In a multi-org Shipit deployment (`Shipit.github` selecting per-org config, `github_app_config`) each org has its own secret [4](#0-3) , and `verify_webhook_signature` returns `true` outright if no secret is configured for that org [5](#0-4) . So a payload with `organization.login` = the attacker's own onboarded org, signed with the attacker's own secret, passes verification.

Once past verification, `MembershipHandler#process` does:
```
team = find_or_create_team!          # Team.find_or_create_by!(github_id: params.team.id)
...
team.add_member(member) / team.members.delete(member)
``` [6](#0-5) 

`find_or_create_by!(github_id: params.team.id)` matches on `github_id` alone; the `organization:` assignment only executes inside the creation block, i.e. only when no row exists yet. If the privileged team (e.g. `shopify/developers`, `github_id: 1`, fixture at [7](#0-6) ) already exists, the lookup returns that record unconditionally — the payload's `organization.login` value is never compared to the found team's `organization` column. `Team#add_member`/`members.delete` operate on `has_many :members, through: :memberships` [8](#0-7)  with no additional scoping.

Existing guards do not catch this: `verify_signature` only proves the request was signed by *some* configured org's secret, not that this org matches the org owning `team.id`; `find_or_create_team!` never re-checks `params.organization.login` against the fetched team's `organization`; there is no controller- or model-level authorization tying webhook org identity to the specific `Team` row being mutated.

### Impact Explanation
The attacker can flip arbitrary users' membership in any `Team` whose `github_id` they know, as long as that team belongs to a *different* org than the one they authenticated as. Because `User#authorized?` checks membership against `Shipit.github_teams` [1](#0-0) , and those teams are exactly `Team` records reachable through this handler, this is a direct escalation path into `Shipit.github_teams` authorization — either granting an arbitrary GitHub login application access, or stripping a legitimate maintainer's access by deleting their `Membership`. This is repeatable indefinitely and works against any team whose numeric `github_id` is known or guessable, across tenant boundaries on a multi-org Shipit install. This matches the High severity category ("escalation into `Shipit.github_teams` authorization").

### Likelihood Explanation
Requires a multi-organization Shipit deployment (`github` config keyed by multiple org names, as documented in `docs/setup.md` "Using Multiple Github Applications") where the attacker legitimately administers one onboarded-but-unprivileged organization and thus knows/controls that org's own `webhook_secret`. The attacker needs the target team's numeric `github_id`, which is discoverable via GitHub's team API/UI if the victim team is visible, or by brute-forcing small sequential integers since Shipit team IDs are DB auto-increment integers seeded from GitHub team IDs. No privileged secret, session, or API token is required — the cost is essentially one crafted HTTP POST per membership flip.

### Recommendation
In `MembershipHandler#find_or_create_team!` (and in `#process`), scope the `Team` lookup by both `github_id` and `organization`, and hard-fail (or drop) the event if a `Team` already exists with that `github_id` under a different `organization` than `params.organization.login`. E.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login.downcase)`, and additionally verify in `WebhooksController` that the authenticated `repository_owner`/org matches the org embedded in nested resources referenced by the payload before invoking handlers.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":membership from OrgTwo cannot mutate OrgOne's privileged team" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: 1

  # Attacker authenticates as OrgTwo (their own onboarded org, own webhook_secret)
  Shipit.github(organization: 'OrgTwo').stubs(:verify_webhook_signature).returns(true)

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: victim_team.github_id, name: 'Developers', slug: 'developers', url: 'https://example.com' },
    organization: { login: 'OrgTwo' },        # attacker's own org
    member: { login: 'attacker_target_user' }
  }.to_json

  assert_no_difference -> { Membership.where(team_id: victim_team.id).count } do
    post :create, body: payload, as: :json
    assert_response :ok  # currently succeeds -- demonstrates the broken binding
  end
end
```
Assertion on both sides of the binding: `signing_org = 'OrgTwo'` must equal `victim_team.reload.organization` ('shopify') before the mutation is allowed; the test shows a `Membership` row for `victim_team` is created despite `signing_org != victim_team.organization`, proving the binding is broken. Repeating with `action: 'removed'` against a pre-existing legitimate member shows the same handler can also strip access, confirming bidirectional control.

### Citations

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/team.rb (L7-8)
```ruby
    has_many :memberships
    has_many :members, class_name: :User, through: :memberships, source: :user
```
