### Title
Cross-tenant `Team` github_id confusion in `MembershipHandler#process` allows escalation into `Shipit.github_teams` authorization - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` resolves the target `Team` purely by the attacker-controlled `team.id` field, with no check that the team actually belongs to the organization whose secret validated the webhook signature. In a multi-tenant Shipit deployment (`secrets.github` keyed by organization), an operator of any onboarded organization can sign a `membership` webhook with their own org's `webhook_secret` while setting `team.id` to the numeric `github_id` of a different, already-synced `Team` used in `Shipit.github_teams`, causing an arbitrary user to be added as a member of that authorization-bearing team.

### Finding Description
Binding claimed: `Membership row for a team in Shipit.github_teams == a membership GitHub actually reports for that team`.

Trace:
- `WebhooksController#verify_signature` looks up the GitHub App config with `Shipit.github(organization: repository_owner)`, and `repository_owner` for a `membership` event resolves to `params.dig('organization', 'login')` since there is no `repository` key on this event type: [1](#0-0) .
- `Shipit.github(organization:)` looks up per-organization config from `secrets.github`, so each onboarded organization has its own independent `webhook_secret`: [2](#0-1) .
- `verify_signature` only checks that the signature matches the secret of the org named in the payload's `organization.login` -- it never checks that `team.id` in the payload actually belongs to that same organization: [3](#0-2) .
- `MembershipHandler#find_or_create_team!` resolves the `Team` solely by `github_id: params.team.id`. If a `Team` with that `github_id` already exists (e.g. a legitimate team previously synced and present in `Shipit.github_teams`), `find_or_create_by!`'s block -- which would otherwise set `organization` from `params.organization.login` -- is skipped entirely, and the pre-existing (victim) row is returned unchanged: [4](#0-3) .
- `process` then unconditionally does `team.add_member(member)` for `action == 'added'`, using `User.find_or_create_by_login!(params.member.login)` where `login` is also attacker-controlled: [5](#0-4) , [6](#0-5) .
- Authorization checks Shipit-wide rely on team membership: `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?`, and `Shipit.github_teams` is built from configured team handles resolved to `Team` rows: [7](#0-6) , [8](#0-7) .

Exploit: attacker administers (or otherwise legitimately controls the webhook secret for) any organization onboarded into the same multi-tenant Shipit instance, e.g. `attacker-org`. They send `POST /webhooks` with `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with `attacker-org`'s own `webhook_secret`, `organization.login: "attacker-org"` (so `verify_signature` passes), `action: "added"`, `team: { id: <victim_team_github_id>, name/slug/url: anything }`, and `member: { login: "<any-github-login>" }`. Because the `Team` row with that `github_id` already exists (synced earlier from the real victim org), the block that would set `organization` is skipped -- the row's `organization`/`slug` remain the victim's -- and a new `Membership` linking the attacker-chosen user to that team is created.

Existing guards do not stop this: `verify_signature` only validates that the request came from *some* org Shipit trusts, not that the reported `team`/`organization` combination is internally consistent; `ExplicitParameters` schema only enforces field presence/types, not cross-field integrity; `drop_unhandled_event` is irrelevant since `membership` is handled; `force_github_authentication`/`User#authorized?` operate downstream on the resulting (poisoned) membership data and have no way to detect the forgery.

### Impact Explanation
An attacker who controls webhook credentials for any single organization onboarded in a multi-tenant Shipit instance can grant arbitrary GitHub logins membership in a `Team` referenced by `Shipit.github_teams` -- the exact set gating access to the entire application via `force_github_authentication`/`User#authorized?`. This is a direct escalation into `Shipit.github_teams` authorization: an unauthorized user becomes "authorized" application-wide (all stacks, deploys, rollbacks) without ever being a real member of the victim GitHub team/org. It is repeatable against any `github_id` the attacker can enumerate (team IDs are small sequential integers) and works for any number of victim teams/tenants sharing the same Shipit instance, so the blast radius spans every tenant whose `Team` rows have already been synced.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment with `secrets.github` configured for multiple organizations (documented, supported configuration -- see `test/dummy/config/secrets_double_github_app.yml`); (2) attacker legitimately controls the webhook secret of at least one onboarded, low-privilege organization; (3) a victim `Team` row with a known/guessable `github_id` already exists (created by any earlier legitimate sync, including via `Shipit.github_teams`/`rake teams:fetch` or a prior membership webhook). No GitHub, Shipit or victim-org secret is needed. Given the attacker only needs their own tenant's secret plus a numeric team ID, this is a low-cost, fully repeatable attack once the multi-org precondition holds.

### Recommendation
In `Team.find_or_create_by!(github_id: params.team.id)`, additionally scope the lookup/creation by the organization derived from the *verified* webhook context (not by trusting `params.organization.login` blindly, but by tying it to the org used in `verify_signature`), and reject/raise when an existing `Team` for that `github_id` has an `organization` different from the organization that signed the request, rather than silently reusing the row.

### Proof of Concept
```ruby
test "membership webhook cannot add members to a team belonging to a different organization" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: X
  original_organization = victim_team.organization
  original_slug = victim_team.slug

  @request.headers['X-Github-Event'] = 'membership'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # attacker-org's own secret verified

  assert_difference -> { Shipit::Membership.count }, 1 do
    post :create, as: :json, body: {
      action: 'added',
      team: { id: victim_team.github_id, name: 'Forged', slug: 'forged', url: 'https://evil.example' },
      organization: { login: 'attacker-org' },
      member: { login: 'attacker_controlled_login' }
    }.to_json
    assert_response :ok
  end

  victim_team.reload
  # Binding check: same victim row, unmodified organization/slug
  assert_equal original_organization, victim_team.organization
  assert_equal original_slug, victim_team.slug
  # Yet an unauthorized membership now exists
  assert victim_team.members.exists?(login: 'attacker_controlled_login')
end
```

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
