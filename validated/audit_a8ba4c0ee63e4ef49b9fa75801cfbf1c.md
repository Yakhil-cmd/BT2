This confirms the vulnerability. `Shipit.github_teams` is populated once via `github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }` [1](#0-0) , and `User#authorized?` checks membership against those team ids: `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [2](#0-1) . The `MembershipHandler#find_or_create_team!` method resolves teams purely by `github_id` with no organization scoping in the `WHERE` clause of `find_or_create_by!`, only setting `organization` inside the creation block which never runs on a hit [3](#0-2) .

Critically, `WebhooksController#verify_signature` authenticates the webhook against `Shipit.github(organization: repository_owner)`, and for a `membership` event `repository_owner` falls back to `params.dig('organization', 'login')` [4](#0-3) . This means the signature is verified using the webhook secret of the organization named in the payload itself — the attacker's own org, if it is one of the configured multi-org apps in `secrets.github` (`Shipit.github_app_config` looks it up by name) [5](#0-4) . There is no cross-check that the `organization.login` in the payload matches the organization that owns the team's `github_id`.

So exploitation requires: the attacker administers a GitHub org that is itself configured as one of Shipit's trusted `github` orgs (with a legitimate webhook secret) — a precondition, not a bypass of authentication itself. Given that, the attacker can create/rename a team with a numeric id equal to an existing privileged `Shipit::Team.github_id` (team ids are low sequential integers, easily brute-forceable or achievable by creating enough teams), then trigger (or replay) a signed `membership` `added` event naming themselves as `member`. `find_or_create_team!` hits the existing privileged `Team` row (e.g., organization `shopify`) instead of creating a new one scoped to the attacker's org, and `team.add_member(member)` adds the attacker's Shipit `User` into that privileged team [6](#0-5) , satisfying `authorized?` and escalating the attacker into `Shipit.github_teams` authorization — access to protected stacks/deploy actions gated by team membership.

This matches an existing test that shows membership webhooks create teams by id without any org binding check [7](#0-6) .

### Title
Membership webhook `find_or_create_team!` resolves teams by `github_id` alone, letting a same-App-config attacker organization hijack another organization's privileged `Team` row - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` looks up `Team` records solely by `github_id`, with no scoping to the webhook's authenticated organization, and only assigns `organization` inside the `find_or_create_by!` creation block (never executed on an existing-record hit). Because GitHub team ids are small sequential integers and are not namespaced by Shipit, an attacker who controls any GitHub organization configured in Shipit's multi-org `github` secrets can craft a team whose id collides with an existing privileged team's `github_id` in another organization, then have a legitimately-signed `membership` webhook add themselves as a member of that pre-existing, differently-owned `Team` row.

### Finding Description
The broken binding: `Team#organization == <organization that authenticated the current webhook>` must hold for every mutation performed through a `membership` webhook, but is only enforced inside the `create` block of `find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` [3](#0-2) . On the find-hit path (an existing `Team` row with that `github_id` already present, e.g. seeded from a different, privileged organization such as `shopify`), the block never runs, so `params.organization.login` is never compared against the found `team.organization`.

`WebhooksController#verify_signature` authenticates the request using `Shipit.github(organization: repository_owner)` where, for membership events (no `repository` key), `repository_owner` falls back to `params.dig('organization', 'login')` — i.e., the payload's own `organization.login` [4](#0-3) . This correctly proves the payload came from *some* org configured in Shipit's `secrets.github` multi-org map, but it does not prove that org owns the `github_id` referenced by `params.team.id`.

Attack flow: attacker administers GitHub org `attacker-org`, which is one of the multiple organizations configured in Shipit's `github:` secrets (a legitimate precondition of multi-tenant Shipit deployments). Attacker creates/renames a team in `attacker-org` whose numeric `id` collides with the `github_id` of a pre-existing `Shipit::Team` from a privileged org (e.g., `shopify`, id 99, part of `Shipit.github_teams`). GitHub emits (or the attacker replays via `POST /webhooks`) a `membership` `added` webhook, correctly signed with `attacker-org`'s webhook secret, containing `team: { id: 99, ... }`, `organization: { login: 'attacker-org' }`, `member: { login: attacker_shipit_user }`. `verify_signature` passes because the signature matches `attacker-org`'s secret. `find_or_create_team!` calls `Team.find_or_create_by!(github_id: 99)`, hits the existing `shopify`-owned row, and `process` calls `team.add_member(member)`, adding the attacker's user to the privileged team without ever touching or validating the `organization` column [6](#0-5) .

Existing guards do not catch this: `verify_signature` only validates which org signed the request, not which org "owns" the referenced `github_id` [8](#0-7) ; the `ExplicitParameters` schema only requires `team.id` be an `Integer` [9](#0-8) ; and `Team` has no uniqueness/organization-scoped validation visible in the model to prevent cross-org collisions [10](#0-9) .

### Impact Explanation
The attacker's Shipit `User` gets added to a `Membership` for a `Team` row that belongs to a different, higher-privileged GitHub organization. Since `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [2](#0-1) , this directly escalates the attacker into `Shipit.github_teams` authorization if the collided team is one of the configured `oauth_teams`. This is a High severity escalation into `Shipit.github_teams` authorization as defined in scope, potentially unlocking access gated on team membership across the whole Shipit instance, not just the attacker's own organization/repositories — a cross-tenant blast radius in multi-org Shipit deployments.

### Likelihood Explanation
Exploitation requires the attacker to administer a GitHub organization that is itself one of the trusted organizations configured in Shipit's `secrets.github` multi-org map (so its `webhook_secret` legitimately signs requests) — this is the realistic scenario for any multi-tenant Shipit install serving several GitHub orgs, some possibly less trusted than others. Given that, the rest of the attack is cheap: GitHub team ids are low, sequential, unnamespaced integers, so an attacker can create several teams in their own org to find/guess a collision with a privileged org's `Shipit::Team.github_id`, then trigger a normal `membership` webhook (real GitHub event or a replayed/synthesized POST signed with their own legitimate secret). No stolen secrets are required beyond the attacker's own legitimately-issued webhook secret for their own org.

### Recommendation
Scope the lookup/creation to the authenticated organization, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and additionally verify on the find-hit path that `team.organization == params.organization.login`, raising/rejecting the event (or logging and no-op) if there is a mismatch, rather than silently operating on a cross-organization `Team` record. Consider also making `github_id` uniqueness scoped by `organization` (or globally unique with a hard failure on mismatch) at the model layer.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb` or a new `test/models/shipit/webhooks/handlers/membership_handler_test.rb`:
1. Create `privileged_team = Shipit::Team.create!(organization: 'shopify', github_id: 99, name: 'Ops', slug: 'ops', api_url: 'https://api.github.com/teams/99')`.
2. Configure/stub Shipit's multi-org github config so `attacker-org` has its own `webhook_secret`, and stub `Shipit.github(organization: 'attacker-org').verify_webhook_signature` to return `true` (simulating a correctly-signed request from `attacker-org`).
3. POST to `/webhooks` with header `X-Github-Event: membership` and a correctly-"signed" body: `{ action: 'added', team: { id: 99, name: 'Evil', slug: 'evil', url: 'https://example.com' }, organization: { login: 'attacker-org' }, member: { login: 'attacker' } }`.
4. Assert `response` is `:ok`.
5. Assert `Shipit::Team.find(privileged_team.id).organization == 'shopify'` (unchanged — proving no re-validation occurred).
6. Assert `Shipit::Team.find(privileged_team.id).members.map(&:login).include?('attacker')` is `true` (proving the attacker was added to the privileged, differently-owned team), demonstrating the organization-binding was never enforced on the found-record path.

### Citations

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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

**File:** test/controllers/webhooks_controller_test.rb (L129-140)
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
```

**File:** app/models/shipit/team.rb (L1-59)
```ruby
# frozen_string_literal: true

module Shipit
  class Team < Record
    REQUIRED_HOOKS = %i[membership].freeze

    has_many :memberships
    has_many :members, class_name: :User, through: :memberships, source: :user

    has_many :github_hooks,
             -> { where(event: REQUIRED_HOOKS) },
             foreign_key: :organization,
             primary_key: :organization,
             class_name: 'GithubHook::Organization',
             inverse_of: false

    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end

      def fetch_and_create_from_github(organization, slug)
        return unless github_team = find_team_on_github(organization, slug)

        create!(github_team:, organization:)
      end

      def find_team_on_github(organization, slug)
        gh_api = Shipit.github(organization:).api
        teams = Shipit::OctokitIterator.new(github_api: gh_api) { gh_api.org_teams(organization, per_page: 100) }
        teams.find { |t| t.slug == slug }
      rescue Octokit::NotFound
      end
    end

    def handle
      "#{organization}/#{slug}"
    end

    def add_member(member)
      members.append(member) unless members.include?(member)
    end

    def refresh_members!
      github_api = Shipit.github(organization:).api
      github_members = Shipit::OctokitIterator.new(github_api.get(api_url).rels[:members])
      members = github_members.map { |u| User.find_or_create_from_github(u) }
      self.members = members
      save!
    end

    def github_team=(github_team)
      self.name = github_team.name
      self.slug = github_team.slug
      self.api_url = github_team.url
      self.github_id = github_team.id
    end
  end
```
