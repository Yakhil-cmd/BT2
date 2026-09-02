### Title
Cross-tenant `Team` identity confusion in `membership` webhook handling due to missing organization re-validation - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` resolves teams via `Team.find_or_create_by!(github_id: params.team.id)`, but the block that sets `team.organization = params.organization.login` only executes when a **new** record is created [1](#0-0) . If a `Team` row with a matching `github_id` already exists for a different organization, `find_or_create_by!` returns that existing row unchanged, and `process` proceeds to call `team.add_member(member)` on it [2](#0-1) , without ever comparing the found team's `organization` against the verified payload's `params.organization.login`.

### Finding Description
The binding that should hold is: `team.organization == params.organization.login` for the *same verified payload*, both before and after `find_or_create_team!` runs. The code never enforces this equality when the `github_id` lookup hits an existing row.

Path: `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event('membership')`, which invokes `MembershipHandler`, after `verify_signature` validates the payload's HMAC using `Shipit.github(organization: repository_owner)` — correctly scoped per-org in the multi-tenant config [3](#0-2) . This guarantees the payload was genuinely signed by GitHub for the attacker's own org (org A). However, once inside `MembershipHandler#process`, the only identity check performed is `Team.find_or_create_by!(github_id: params.team.id)` [1](#0-0) . `github_id` has no uniqueness DB constraint (only `organization+slug` is uniquely indexed) [4](#0-3) , and `Team` has no model-level validation preventing a lookup mismatch either [5](#0-4) .

If `params.team.id` numerically matches an existing `Team#github_id` belonging to organization B (e.g. one of the fixtures `shopify_developers` with `github_id: 1` or `cyclimse_cooks` with `github_id: 2` [6](#0-5) ), then `find_or_create_by!` returns team B unchanged — its `organization` stays `'B'` even though the verified signer was org A. `team.add_member(member)` then appends the attacker's `User.find_or_create_by_login!(params.member.login)` into team B's `memberships` [7](#0-6) .

If team B is one of `Shipit.github_teams` (configured via `github.oauth.teams`) [8](#0-7) , the attacker's login becomes a member of a privileged team, and `User#authorized?` — `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` — now returns `true` for that login [9](#0-8) , granting full access to Shipit for the target organization.

**Existing guards that do not stop this**: `verify_signature` only proves the payload's *sender org* is genuine (org A); it says nothing about the numeric `team.id` inside the payload, which is entirely controlled by whatever GitHub assigns when the attacker creates/manages a team in their own org A. `find_or_create_by!`'s creation block is the only place `organization` is set, and it is skipped on the "found" branch — there is no explicit check comparing `team.organization` to `params.organization.login` on the found path.

**Critical caveat on exploitability**: `params.team.id` is GitHub's own globally-assigned, monotonically increasing team identifier. It is not a value the attacker can freely "craft" — they can only observe whichever ID GitHub happens to assign to teams they create/manage in their own org. Reliably producing a numeric collision with a specific pre-existing target `Team#github_id` therefore requires either extraordinary coincidence, a pre-existing team the attacker already happens to control with a matching ID, ID reuse/recycling on GitHub's side, or a non-github.com deployment (e.g., a self-hosted GitHub Enterprise Server domain configured per-organization in `Shipit.github`) where the attacker might control ID allocation. This is not a value the attacker can pick at will on github.com.

### Impact Explanation
If the collision occurs, the attacker's GitHub login is durably inserted as a member of a `Team` row that may be part of `Shipit.github_teams`, escalating them into cross-tenant Shipit authorization — matching the "High - escalation into `Shipit.github_teams` authorization" category. This grants the attacker `force_github_authentication`-gated access to another organization's Shipit deployment (stacks, deploys, potentially secrets), repeatable for as long as the colliding `github_id` remains valid and the `membership` webhook fires (e.g. on every team-membership change in the attacker's org).

### Likelihood Explanation
Preconditions: the attacker must own/administer a GitHub organization that is already configured with a legitimate GitHub App in Shipit's multi-tenant `Shipit.github` map (so their `membership` webhooks pass `verify_signature`), and a `Team` with a colliding `github_id` must already exist for a different, privileged organization. The attacker has no mechanism to choose the exact `team.id` value delivered in a genuine GitHub webhook — GitHub itself assigns this ID, globally and monotonically, when the attacker creates/manages a team in their own org. Achieving a deliberate numeric collision with an arbitrary pre-existing target ID on github.com is not something the attacker can engineer on demand; it would require coincidence, ID reuse, or an unusual per-organization GitHub Enterprise Server deployment. This significantly limits real-world feasibility, but the underlying code defect (missing re-validation of `team.organization` on the "found" branch of `find_or_create_by!`) is real and independent of how the collision arises (it would equally be triggered by GitHub-side team-ID recycling or an operator misconfiguration).

### Recommendation
In `MembershipHandler#find_or_create_team!`, after resolving the team, explicitly verify `team.organization == params.organization.login` (case-insensitively) and raise/drop the event if they differ, rather than silently trusting whatever record `find_or_create_by!` returns. Consider scoping the lookup itself, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and/or adding a DB-level check ensuring `github_id` uniqueness is validated against `organization` consistency.

### Proof of Concept
Minitest plan (extending `test/controllers/webhooks_controller_test.rb`, using existing signature stub pattern):
1. Use fixture `shipit_teams(:cyclimse_cooks)` (`github_id: 2`, `organization: 'cyclimse'`) as the foreign privileged team B.
2. Stub `Shipit.github(organization: 'shopify').verify_webhook_signature` (or use the existing `GithubHook.any_instance.stubs(:verify_signature).returns(true)` pattern) to simulate a genuinely-signed webhook for organization `'shopify'` (org A).
3. POST a `membership` event: `action: 'added'`, `team: { id: 2, name: 'Cooks', slug: 'cooks', url: '...' }`, `organization: { login: 'shopify' }`, `member: { login: 'attacker' }`.
4. Assert before/after: `shipit_teams(:cyclimse_cooks).reload.organization` is still `'cyclimse'` (unchanged) even though the verified signer was `'shopify'` — i.e. `team.organization != params.organization.login`.
5. Assert `shipit_teams(:cyclimse_cooks).members.map(&:login)` now includes `'attacker'`.
6. Assert `User.find_by(login: 'attacker').authorized?` returns `true` when `Shipit.stubs(:github_teams).returns([shipit_teams(:cyclimse_cooks)])`, demonstrating the escalation into `Shipit.github_teams` authorization for org `cyclimse` via a webhook verifiably signed for org `shopify`.

### Citations

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

**File:** test/fixtures/shipit/teams.yml (L1-17)
```yaml
# Read about fixtures at http://api.rubyonrails.org/classes/ActiveRecord/FixtureSet.html

shopify_developers:
  id: 1
  github_id: 1
  organization: shopify
  slug: developers
  name: Developers
  api_url: https://example.com/shopify/developers

cyclimse_cooks:
  id: 2
  github_id: 2
  organization: cyclimse
  slug: cooks
  name: Cooks
  api_url: https://example.com/cyclimse/cooks
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
