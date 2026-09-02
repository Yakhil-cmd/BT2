This confirms the vulnerability. The key facts:

- `Shipit.github(organization:)` looks up config keyed by `organization` param, which the controller supplies via `repository_owner` derived from `params.dig('organization', 'login')` in the multi-tenant config schema. [1](#0-0)  This means signature verification uses the *attacker's own* org config, verifying against the attacker's own `webhook_secret`. [2](#0-1) 
- `MembershipHandler#find_or_create_team!` calls `Team.find_or_create_by!(github_id: params.team.id)`, keyed purely on the numeric `github_id`, with the block (which sets `team.organization = params.organization.login`) only executing on creation, not on lookup of an existing record. [3](#0-2)  So if a `Team` with that `github_id` already exists (e.g. `shopify_developers`), the found record's `organization` field is never checked against `params.organization.login`.
- `team.add_member(member)` unconditionally appends the member to that team's `members`. [4](#0-3) 
- `User#authorized?` grants access if the user belongs to any team in `Shipit.github_teams`. [5](#0-4)  `Shipit.github_teams` is built from `github.oauth_teams`, resolved via `Team.find_or_create_by_handle`, meaning teams are matched by `github_id` values that are globally namespaced integers from GitHub, not scoped per-organization inside Shipit's own DB record. [6](#0-5) 

The broken binding is: the org that authenticates the webhook (`params.organization.login`, verified against that org's `webhook_secret`) is assumed to equal the org owning the `Team` matched by `params.team.id`, but `find_or_create_by!(github_id:)` never enforces that equality for pre-existing teams.

The existing test suite already demonstrates the intended flow for a legitimate org (`test/controllers/webhooks_controller_test.rb` "`:membership creates the mentioned team on the fly`" and "`:membership can append an user membership`" both use `organization: { login: 'shopify' }` matching the fixture's owning org), but there is no test asserting rejection when `organization.login` doesn't match the team's `organization`. [7](#0-6) 

### Title
Cross-organization webhook confusion lets an attacker join an arbitrary `Team` via forged `membership` webhook matched only by `team.id` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a webhook only against the organization named in the payload itself, and `MembershipHandler#find_or_create_team!` looks up the target `Team` solely by the numeric `github_id`, never checking that the authenticated organization actually owns that team. An attacker who runs their own GitHub App/org can therefore submit a self-signed `membership` webhook naming a foreign `team.id` and add themselves to any pre-existing Shipit `Team`, including ones listed in `Shipit.github_teams`.

### Finding Description
The broken binding: `params.organization.login` (the org whose `webhook_secret` verified the request via `Shipit.github(organization: repository_owner)`) is assumed to equal the `organization` that owns the `Team` row matched by `params.team.id`. This is never actually checked.

Path: `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` [8](#0-7)  and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. In the multi-tenant config schema, `Shipit.github` builds a `GitHubApp` from that org's own config entry [1](#0-0) , so an attacker who registers their own org/app in Shipit's config and knows their own `webhook_secret` passes this check trivially using their own org's login in both `repository.owner.login`/`organization.login`.

`MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` [3](#0-2) . The block only runs when a new record is created; if a `Team` with that `github_id` already exists (any pre-existing team, e.g., one in `Shipit.github_teams`), it's returned unmodified regardless of what `params.organization.login` says. `team.add_member(member)` then unconditionally appends the attacker (whose `login` is fully attacker-controlled in `params.member.login`) to that team's members [4](#0-3) .

Since GitHub team IDs are just integers and the attacker can put any value they want in `params.team.id`, they can guess/enumerate/brute-force `github_id` values or, if they've observed a target org's team IDs from any public source, target a specific `Team` row directly. Note `find_or_create_by!` will raise `ActiveRecord::RecordInvalid` if the org fields conflict on the uniqueness constraints only when creating a new row — it does not raise when matching an existing row by `github_id` alone.

`User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [5](#0-4) , so once the forged `Membership` row exists, the attacker's account (auto-created via `User.find_or_create_by_login!`) becomes authorized in Shipit if the targeted team is in `Shipit.github_teams`.

None of the documented guards prevent this: `verify_signature` only proves the request was signed by *some* org's secret, not that it's the org owning the target team; the `ExplicitParameters` schema in `MembershipHandler` only validates types/presence, not cross-field integrity; there is no `force_github_authentication` or `require_permission!` check on this webhook path since it's unauthenticated by design (webhooks use signatures, not sessions).

### Impact Explanation
This is an authentication/authorization bypass: an attacker can escalate into any `Shipit.github_teams` membership (High/Critical per the given severity taxonomy: "escalation into `Shipit.github_teams` authorization"), gaining `User#authorized?` == true and thus general Shipit access, without ever compromising the target organization's real `webhook_secret`, GitHub App credentials, or session. Blast radius is per-team and per-installation-wide since `Team` rows are global, not scoped to the requesting org; a single Shipit instance serving multiple orgs is at highest risk. Repeatable per attacker-controlled webhook POST, and the attacker can add themselves to multiple existing teams by repeating with different `team.id` values.

### Likelihood Explanation
Preconditions: the attacker needs the target `Team.github_id` value (a numeric GitHub team ID — team IDs are visible in various GitHub API responses/URLs and are not treated as secret by GitHub), and Shipit must be configured with multiple GitHub organizations/apps (the "multi-tenant" `github_app_config` path) so that the attacker can register their own org with a genuine `webhook_secret` under `Shipit.github(organization: attacker_org)`. No other Shipit or GitHub secret is required. Cost is a single crafted HTTP POST; fully repeatable and scriptable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that `params.organization.login` matches the existing team's `organization` field (case-insensitively, consistent with `Team.find_or_create_by_handle`'s downcasing) before allowing `add_member`/`members.delete` to proceed; raise/drop the event (e.g., return early or raise `ArgumentError`) on mismatch instead of silently reusing the record. Alternatively, scope the lookup itself: `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)` so a mismatched org never matches an existing row.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":membership from a different org cannot add member to an existing team it doesn't own" do
  target_team = shipit_teams(:shopify_developers)
  attacker_org = 'attacker-org'

  # Attacker signs with their own org's webhook secret (simulated via stub since no live GitHub secret is used)
  Shipit.stubs(:github).with(organization: attacker_org).returns(
    stub(verify_webhook_signature: true)
  )

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: target_team.github_id, name: target_team.name, slug: target_team.slug, url: target_team.api_url },
    organization: { login: attacker_org },       # <- does NOT own target_team
    member: { login: 'attacker-login' },
    repository: { owner: { login: attacker_org } }
  }.to_json

  assert_no_difference -> { target_team.memberships.count } do
    post :create, body: payload, as: :json
  end
  # Currently FAILS: membership is created, and User.find_by(login: 'attacker-login').authorized? becomes true
  # if target_team is among Shipit.github_teams.
end
```
Both sides of the equality: LHS = organization that verified the signature (`attacker_org`, verified via `Shipit.github(organization: 'attacker-org').verify_webhook_signature`); RHS = organization owning `target_team` (`shopify`, the pre-existing `Team#organization`). Before the fix these are unequal yet the write proceeds; after the fix, the write must be rejected when LHS != RHS.

### Citations

**File:** lib/shipit.rb (L170-181)
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
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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

**File:** test/controllers/webhooks_controller_test.rb (L129-165)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end

    test ":membership creates the mentioned user on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      Shipit.github.api.expects(:user).with('george').returns(george)
      assert_difference -> { User.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'george' }).to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can delete an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, -1 do
        post :create, body: membership_params.merge(action: 'removed').to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can append an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'bob' }).to_json, as: :json
        assert_response :ok
      end
    end
```
