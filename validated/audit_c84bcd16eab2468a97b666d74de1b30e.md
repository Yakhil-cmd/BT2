### Title
`Team.find_or_create_by_handle` returns pre-existing, webhook-populated Team rows without re-verifying GitHub membership when an operator later adds that Team's handle to `Shipit.github_teams` - ([File: app/models/shipit/team.rb])

### Summary
`Shipit::Webhooks::Handlers::MembershipHandler#process` creates `Team`/`Membership` rows for any organization whose configured `GithubApp` webhook signature verifies, with no check anywhere in `Handler`, `Shipit::Webhooks`, or `WebhooksController` that the organization/team is a member of `Shipit.github_teams`. When an operator later trusts that team by adding its `organization/slug` handle to the `oauth.teams` config, `Team.find_or_create_by_handle` returns the already-existing row (and its pre-existing `Membership` rows) verbatim instead of re-fetching membership from GitHub, so previously-recorded members become authorizing without re-validation.

### Finding Description
The invariant an operator would reasonably expect is: `Membership rows counted by User#authorized? for a Team in Shipit.github_teams == memberships that were verified against GitHub *after* that team became trusted`. That equality does not hold.

Path:
1. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) resolves `Shipit.github(organization: repository_owner)` purely from `secrets.github` config keys — it has no dependency on `Shipit.github_teams` at all: [1](#0-0) . Any organization that has its own configured `GithubApp` entry (added by the operator for repo-hosting purposes, unrelated to login authorization) passes signature verification with its own legitimate, GitHub-issued signature.
2. `Shipit::Webhooks.for_event('membership')` unconditionally dispatches to `MembershipHandler`, with no org/team allow-list check in the dispatch table: [2](#0-1) .
3. `MembershipHandler#process` writes `Team.find_or_create_by!(github_id: ...)` and adds/removes `Membership` rows purely from the payload, again without consulting `Shipit.github_teams`: [3](#0-2) .
4. Later, when an operator adds `"org/slug"` to `github.oauth.teams` to actually grant login access, `Shipit.github_teams` calls `Team.find_or_create_by_handle(t)` for each configured handle: [4](#0-3) .
5. `Team.find_or_create_by_handle` first does a local `find_by(organization:, slug:)`, and only falls back to `fetch_and_create_from_github` (a live GitHub API call) if no local row exists: [5](#0-4) . If the team/membership rows were already created by step 3 (before the operator ever trusted this org), the existing rows — including any `Membership`s inserted while the org was untrusted — are returned as-is, with no call to `refresh_members!`.
6. `User#authorized?` then trusts these rows directly: `teams.where(id: Shipit.github_teams.map(&:id)).exists?`: [6](#0-5) .

A full re-sync only happens if the operator manually runs `rake teams:fetch`, which calls `team.refresh_members!` and overwrites the member list from GitHub: [7](#0-6)  and [8](#0-7) . Nothing in the request-serving path (`force_github_authentication` → `User#authorized?`) enforces that this refresh has run before trusting the config change, so there is a window — potentially indefinite if the rake task is never invoked before the next login attempt — where stale, pre-trust membership rows silently authorize.

### Impact Explanation
This is a TOCTOU escalation into `Shipit.github_teams` authorization (High per the scoped severity list). A user who was recorded as a member of a team/org that was configured in Shipit for unrelated purposes (e.g., repo hosting) but not yet trusted for login can, once an operator adds that org/team handle to `oauth.teams`, be granted Shipit login access immediately and without re-verification, purely because their `Membership` row already existed. This affects `force_github_authentication`/`User#authorized?` gating, i.e., who can log into and use the whole Shipit instance — a broad blast radius across a multi-tenant deployment.

### Likelihood Explanation
This requires: (a) a multi-org Shipit deployment where more than one GitHub organization is configured for a purpose other than login (a legitimate, documented multi-tenant setup, per `secrets_double_github_app.yml`-style config and `Shipit.github_app_config`); (b) that a `membership` webhook fires for that org (a normal GitHub event, genuinely signed by GitHub, requiring no secret knowledge by the attacker — only that they can trigger a real team-membership change in an org Shipit already has configured); and (c) that an operator later adds that exact `organization/slug` to `oauth.teams` without first running `rake teams:fetch`. Given the setup docs explicitly call out the manual refresh step as separate from the config change, this ordering gap is realistic, not contrived.

### Recommendation
Make `Team.find_or_create_by_handle` always resolve/refresh membership from the GitHub API (via `fetch_and_create_from_github`/`refresh_members!`) whenever a team transitions into the `Shipit.github_teams` set, rather than trusting locally cached rows created before that trust existed. Alternatively, scope `MembershipHandler#process` (and `Team` creation generally) to only persist `Membership` rows for organizations already present in `Shipit.github_teams`, or mark such out-of-scope teams/memberships as unverified until a re-sync occurs.

### Proof of Concept
Minitest plan (`test/models/shipit/team_test.rb` or `test/models/user_test.rb` style, no live GitHub):
1. Create a `Team` and `Membership` fixture/row for `organization: "outside-org", slug: "devs"` directly (simulating the effect of a previously-processed `membership` webhook from an org not in `Shipit.github_teams`), assigning a `User` (`attacker`) as a member.
2. Assert `attacker.authorized?` is `false` while `Shipit.stubs(:github_teams).returns([])` or a stub not including this team — establishing the "before" side of the equality.
3. Stub `Shipit.github.oauth_teams` (or `Shipit.stubs(:github_teams)`) to include `"outside-org/devs"`, and stub `Team.find_or_create_by_handle` to go through its real local `find_by` path (do **not** stub `fetch_and_create_from_github`; assert it is never called, e.g. `Team.expects(:fetch_and_create_from_github).never`).
4. Assert `attacker.authorized?` is now `true`, without any `refresh_members!`/GitHub API call having occurred — proving the pre-existing, unverified `Membership` silently became authorizing once the handle was added to config.

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

**File:** app/models/shipit/webhooks.rb (L19-20)
```ruby
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/models/shipit/team.rb (L18-21)
```ruby
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end
```

**File:** app/models/shipit/team.rb (L45-51)
```ruby
    def refresh_members!
      github_api = Shipit.github(organization:).api
      github_members = Shipit::OctokitIterator.new(github_api.get(api_url).rels[:members])
      members = github_members.map { |u| User.find_or_create_from_github(u) }
      self.members = members
      save!
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** lib/tasks/teams.rake (L1-16)
```text
# frozen_string_literal: true

namespace :teams do
  desc "Import the members of each team configured through the github.oauth.teams config"
  task fetch: :environment do
    Shipit.github_teams.each do |team|
      puts "Fetching @#{team.handle} members"
      begin
        team.refresh_members!
      rescue Octokit::Unauthorized, Octokit::NotFound => e
        puts "Failed to fetch @#{team.handle} members. Do you have enough permissions?"
        puts "#{e.class}: #{e.message}"
      end
    end
  end
end
```
