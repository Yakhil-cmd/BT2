### Title
Cross-organization Team membership escalation via unsigned webhook and unscoped `github_id` lookup - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` authenticates a webhook only against the `webhook_secret` configured for the organization named in the *payload* itself (`repository_owner`), and `GitHubApp#verify_webhook_signature` treats a blank secret as automatically verified. `MembershipHandler#find_or_create_team!` then looks up a `Team` purely by `github_id`, a column with no organization scoping, so a webhook that authenticates as one (attacker-controlled, secret-less) organization can mutate a `Team` record that actually belongs to a different, secured organization.

### Finding Description
The broken binding, stated as an equality that must hold but does not: `organization_that_signed_the_bytes (repository_owner in the payload) == organization_that_owns_the_mutated_Team_row (team.organization on the existing Team)`.

Trace:
1. `repository_owner` is read straight from attacker-supplied JSON: `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) .
2. `verify_signature` resolves `Shipit.github(organization: repository_owner)` and calls `verify_webhook_signature` [2](#0-1) . If that org's `GitHubApp` has no `webhook_secret` configured, `verify_webhook_signature` short-circuits to `true` regardless of body or signature header: `return true unless webhook_secret` [3](#0-2) .
3. `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` [4](#0-3) . `github_id` is not scoped by `organization` anywhere in the `Team` model — there is no `validates :github_id, uniqueness: { scope: :organization }` or equivalent, and the finder query itself has no organization filter [5](#0-4) . If a `Team` row already exists with that `github_id` (created earlier via legitimate GitHub sync for a different, secured org), it is returned unchanged — the `organization:`/`github_team=` block in `find_or_create_by!` only runs on creation, not on match.
4. `process` then does `team.add_member(User.find_or_create_by_login!(params.member.login))` [6](#0-5) , `add_member` appends to `members` unconditionally if not already present [7](#0-6) .

No other guard intervenes: `drop_unhandled_event` only checks that a handler exists for the event type, not payload authenticity [8](#0-7) ; the `ExplicitParameters` schema in `MembershipHandler` only validates types/presence, not organizational ownership of `team.id` [9](#0-8) .

Attacker request: `POST /webhooks` with `X-Github-Event: membership`, body `{'organization':{'login':'org-with-no-secret'}, 'team':{'id':<victim_team_github_id>,'slug':'x','name':'x','url':'x'}, 'member':{'login':'attacker-handle'}, 'action':'added'}`, where `org-with-no-secret` is any org configured in `Shipit.github_apps` without a `webhook_secret` (attacker needs no secret, no signature header, since `verify_webhook_signature` returns `true` for blank secret).

### Impact Explanation
The attacker adds their own GitHub-linked `User` as a `Membership` of a `Team` belonging to a completely different, secured organization, without ever authenticating against that organization's webhook secret. Since `Shipit.github_teams` (referenced in `app/controllers/concerns/shipit/authentication.rb` and `app/models/shipit/user.rb`) is used for authorization decisions, this is a direct escalation into `Shipit.github_teams` authorization — matching the "High: escalation into `Shipit.github_teams` authorization" impact category. The attack is repeatable against any `github_id` the attacker can learn (team IDs are often discoverable via public GitHub API) and against any number of teams/organizations, as long as at least one org in `Shipit.github_apps` lacks a `webhook_secret`.

### Likelihood Explanation
Preconditions: (a) at least one organization configured in `Shipit.github_apps` without a `webhook_secret` — a realistic and not-uncommon misconfiguration, since `webhook_secret` is optional per-org in `GitHubApp#initialize` (`@webhook_secret = @config[:webhook_secret].presence`); (b) a `Team` row already existing for the victim org with a known `github_id` (created via normal team sync, e.g. `lib/tasks/teams.rake` or `find_or_create_by_handle`). Attacker cost is a single unauthenticated HTTP POST with a guessable/discoverable numeric GitHub team ID — no secrets, sessions, or tokens required, fully consistent with the stated unprivileged-attacker model.

### Recommendation
Scope the `Team` lookup in `find_or_create_team!` by both `github_id` and `organization` (matching `params.organization.login`), and reject/ignore the webhook if an existing `Team` with that `github_id` belongs to a different organization than the one asserted in the payload. Additionally, consider requiring a non-blank `webhook_secret` for all configured organizations (or refusing to accept webhooks for orgs with no secret at all) so that `verify_webhook_signature`'s blank-secret bypass cannot be leveraged as a "free" authentication path for arbitrary payload organizations.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb` or `test/models/webhooks/handlers/membership_handler_test.rb` (both currently excluded from scope, but describing the shape for handoff):
1. Create `secured_org` with a `webhook_secret` configured in test `Shipit.github_apps`, and `org_with_no_secret` with no `webhook_secret`.
2. Create `Team.create!(organization: 'secured_org', github_id: 999, slug: 'victims', name: 'Victims', api_url: 'x')`.
3. Assert precondition: `Membership.exists?(team: victim_team, user: attacker)` is `false`.
4. POST `/webhooks` with header `X-Github-Event: membership` (no valid `X-Hub-Signature` needed) and body `{organization: {login: 'org_with_no_secret'}, team: {id: 999, slug: 'x', name: 'x', url: 'x'}, member: {login: 'attacker-handle'}, action: 'added'}`.
5. Assert response is `200 OK` and `Membership.exists?(team: victim_team, user: User.find_by(login: 'attacker-handle'))` is now `true`, proving cross-org membership escalation without possessing `secured_org`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** lib/shipit/github_app.rb (L76-77)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-28)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
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
