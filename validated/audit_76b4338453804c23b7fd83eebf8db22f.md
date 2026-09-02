### Title
Membership webhook resolves `User` purely by `login` string with no `github_id`/`member.id` anchor, letting a genuine webhook from an unrelated org corrupt another user's `Membership` records - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` resolves the acted-upon user via `Shipit::User.find_or_create_by_login!(params.member.login)`, which matches an existing `User` row purely by the `login` column, never checking `github_id` or any numeric identifier from the payload. Because the `membership` webhook's `team` lookup is likewise keyed only on `team.github_id` (not scoped to the signing organization), a genuinely GitHub-signed webhook from an org the attacker controls can attach an unrelated, pre-existing Shipit `User` (or even a genuinely privileged `Team`) to a `Membership` row it never actually earned.

### Finding Description
Broken binding (before vs after):
- Expected: `Membership(user_id, team_id)` should only be created when the GitHub identity performing the join (`member.id`/`github_id`) matches the `User` row being mutated, AND the `team.id` in the payload is scoped to the organization that actually signed the webhook (`params.organization.login`).
- Actual: `User.find_or_create_by_login!` at [1](#0-0)  does `find_or_create_by!(login:)` — a pure string match on `login`, with no comparison to any numeric `github_id`. The `params` schema for `MembershipHandler` never even requires `member.id` at [2](#0-1) .
- `find_or_create_team!` matches `Team.find_or_create_by!(github_id: params.team.id)` at [3](#0-2)  — if a `Team` with that `github_id` already exists (e.g., a privileged team from `Shipit.github_teams`), it is returned and mutated regardless of whether `params.organization.login` matches that team's stored `organization`. The `organization` field is only set inside the `create!` block, i.e., only on first creation, never validated on lookup.
- `verify_signature` at [4](#0-3)  only proves the payload was signed by the org named in `params.organization.login` (`repository_owner` fallback) — it proves nothing about the `team.id` or `member.login` values inside that payload being consistent with that org.
- Exploit flow: an attacker who administers their own onboarded GitHub organization (a real Shipit-configured org, but not privileged/team-restricted) adds any known GitHub user (or even names an arbitrary team id) to a team in their own org. GitHub fires a genuinely signed `membership` `added` event. `MembershipHandler#process` at [5](#0-4)  resolves `member` to whatever pre-existing `Shipit::User` row shares that `login` string (created earlier via any unrelated flow such as PR authorship, `find_or_create_from_github`, etc.) and calls `team.add_member(member)`, writing a new `Membership` for a team the victim account never actually joined.
- None of the listed guards catch this: `verify_signature` validates only the org that signed, not per-field consistency; `ExplicitParameters` only checks types/presence, not identity binding; `User#authorized?` at [6](#0-5)  directly consumes the `teams` association populated by this unguarded write.

### Impact Explanation
A `Membership` row is written against an existing `User` for a `Team` the underlying GitHub account never joined, directly corrupting the input to `User#authorized?`. If the colliding/target `team.github_id` is one of the teams backing `Shipit.github_teams`, this becomes an authorization-boundary violation (High: escalation into `Shipit.github_teams` authorization) since `authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?`. At minimum, it's a cross-tenant integrity violation of the `Membership` table, repeatable for any `User` login the attacker can name and any `Team` `github_id` they can guess/discover, from a single genuinely signed webhook their own org can legitimately emit.

### Likelihood Explanation
Requires: (1) the attacker administers a real GitHub organization already onboarded/configured in Shipit's `secrets.github` (so their webhook is genuinely signed), and (2) either they know a target `User`'s GitHub login that already exists in Shipit's DB, and/or they know/guess the numeric `github_id` of a privileged `Team`. Team/user GitHub IDs are not secret (discoverable via public GitHub API calls), and the attacker fully controls the "add member to team" action inside their own org, making this cheap and repeatable without needing any Shipit credentials, session, or GitHub App secret.

### Recommendation
Anchor `MembershipHandler` identity resolution to numeric IDs, not strings: require `member.id` in the params schema and resolve/create via `github_id` (mirroring `User.find_from_github`/`find_or_create_from_github`) instead of `find_or_create_by_login!`. Additionally, scope `find_or_create_team!` lookups to `github_id` AND `organization: params.organization.login` together, rejecting the event (or logging/aborting) if an existing `Team` with that `github_id` belongs to a different organization than the one that signed the webhook.

### Proof of Concept
```ruby
test ":membership does not attach an existing user by login collision from another team" do
  victim = shipit_users(:victim, login: 'victim') # pre-existing user, unrelated org
  attacker_team = shipit_teams(:attacker_org_team)

  @request.headers['X-Github-Event'] = 'membership'
  post :create, body: {
    action: 'added',
    team: { id: attacker_team.github_id, name: attacker_team.name, slug: attacker_team.slug, url: attacker_team.api_url },
    organization: { login: 'attacker-org' },
    member: { login: 'victim' },
    repository: { owner: { login: 'attacker-org' } }
  }.to_json, as: :json

  assert_response :ok
  # Assert the broken binding: Membership written for victim's real User row
  # against a team whose org was never actually joined by that GitHub account.
  refute Membership.exists?(user: victim, team: attacker_team),
    "Membership should not be created without verifying member identity (github_id) and team/org consistency"
end
```

### Citations

**File:** app/models/shipit/user.rb (L22-28)
```ruby
    def self.find_or_create_by_login!(login)
      find_or_create_by!(login:) do |user|
        # Users are global, any app can be used
        # This will not work for users that only exist in an Enterprise install
        user.github_user = Shipit.github.api.user(login)
      end
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
