### Title
Cross-organization team-membership forgery via `Shipit::Webhooks::Handlers::MembershipHandler` — ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the signing `GithubApp` (and therefore the `webhook_secret` to validate against) using an attacker-controlled field of the JSON body (`organization.login`/`repository.owner.login`), while `MembershipHandler` looks up the `Team` to mutate solely by the attacker-controlled numeric `team.id`, with no check that the signing organization owns that team. An attacker who controls (or has been given) the `webhook_secret` of any single low-security org configured in Shipit can therefore forge a `membership` event naming a *different* org's `Team` (one listed via `Shipit.github_teams`) and add an arbitrary GitHub login as a member of it.

### Finding Description
Binding claimed to hold: `org(webhook_secret used to verify signature) == org(owner of the Shipit::Team mutated by MembershipHandler)`.

Trace:
- `WebhooksController#verify_signature` picks the app config with `Shipit.github(organization: repository_owner)`, where `repository_owner` comes from `params.dig('repository','owner','login') || params.dig('organization','login')` — both attacker-supplied JSON fields. [1](#0-0) [2](#0-1) 
- `MembershipHandler#process` looks up (or creates) the team by `github_id: params.team.id`, an attacker-supplied numeric ID, and only sets `team.organization` inside the `find_or_create_by!` block, which executes **only when a new record is created**: [3](#0-2) 
- If a `Team` row with that `github_id` already exists (which is the normal state for any team referenced in `Shipit.github_teams`, since `Shipit.github_teams` eagerly resolves/creates those Team rows via `Team.find_or_create_by_handle`), the existing record — bound to the real victim organization — is reused unchanged, and `team.add_member(member)` writes a `Membership` for it: [4](#0-3) [5](#0-4) [6](#0-5) 
- The `member.login` value is turned into (or matched against) a real `Shipit::User` via `User.find_or_create_by_login!`, which fetches the real GitHub user by login from GitHub's API and stores their real `github_id`: [7](#0-6) 
- On a subsequent legitimate GitHub OAuth login, the attacker is matched to the *same* `User` row by `github_id` (`find_by(github_id: github_user.id)`), so the forged `Membership` attaches to their real Shipit session: [8](#0-7) [9](#0-8) 
- Authorization then trusts this: `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?`: [10](#0-9) 

Exploit request: POST `/webhooks` with header `X-Github-Event: membership` and body
```json
{"action":"added","team":{"id":<victim_team_github_id>,"name":"x","slug":"x","url":"x"},
 "organization":{"login":"attacker-org"},"member":{"login":"<attacker_github_login>"}}
```
signed with `X-Hub-Signature` computed using `attacker-org`'s own `webhook_secret` (an org the attacker administers/controls in a multi-org Shipit deployment, per `docs/setup.md`'s "Using Multiple Github Applications"). `verify_signature` resolves and validates against `attacker-org`'s secret and passes, even though the payload's `team.id` targets a completely different, victim organization's team.

None of the existing guards catch this: `verify_signature` never compares the verifying org to `params.team`'s owning org; `ExplicitParameters` only validates types/presence, not cross-field org ownership; `drop_unhandled_event` only checks a handler exists for the event name.

### Impact Explanation
A single forged POST grants the attacker (or any GitHub login they name) `Membership` in any `Shipit::Team` whose numeric GitHub `id` they can supply — including teams enumerated in `Shipit.github_teams`, which gates `User#authorized?` (application-wide login authorization) and can gate stack/team-scoped features. This is a genuine escalation "into `Shipit.github_teams` authorization" (High per the stated severity taxonomy), repeatable against any team ID the attacker knows, and reachable using only the webhook secret of any single low-security org configured in the multi-tenant Shipit instance — the attacker never needs the victim org's secret, a Shipit session, or an API token.

### Likelihood Explanation
Preconditions: (1) Shipit configured with multiple GitHub orgs/apps (documented, common setup) where the attacker controls at least one low-security org's `webhook_secret`; (2) the victim's authorized `Shipit::Team` row already exists in the DB with its real `github_id` (near-certain in a live deployment, since `Shipit.github_teams` is evaluated on every authorization check and eagerly creates/finds these rows); (3) attacker knows/guesses the victim team's numeric GitHub team ID (not secret, but not always trivially public). Attacker cost is a single crafted HTTP POST, no privileged credentials required beyond one org's webhook secret they legitimately hold.

### Recommendation
In `MembershipHandler`, verify that `params.organization.login` (the org whose signature verified the request) matches the resolved `Team#organization` (case-insensitively) before mutating membership — reject/no-op otherwise. Additionally, `find_or_create_team!` should scope lookup by `(github_id, organization)` rather than `github_id` alone, and never allow a webhook verified for org A to attach/detach members of a `Team` bound to org B.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`):
```ruby
test ":membership signed by a different org cannot mutate another org's team" do
  victim_team = shipit_teams(:shopify_developers) # organization == 'shopify'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulate valid sig from attacker-org's secret
  @request.headers['X-Github-Event'] = 'membership'

  body = {
    action: 'added',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker_login' }
  }.to_json

  assert_no_difference -> { victim_team.memberships.count } do
    post :create, body:, as: :json
  end
end
```
Binding assertion before: `signing_org = "attacker-org"`, `team.organization = "shopify"` (unequal). After the fix, the handler must detect `signing_org != team.organization` and skip the mutation, keeping `victim_team.memberships.count` unchanged; without the fix, `Membership.count`/`victim_team.memberships.count` increases, demonstrating the forgery.

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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/models/shipit/team.rb (L17-27)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end

      def fetch_and_create_from_github(organization, slug)
        return unless github_team = find_team_on_github(organization, slug)

        create!(github_team:, organization:)
      end
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

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

**File:** app/models/shipit/user.rb (L50-54)
```ruby
    def self.find_from_github(github_user)
      return unless github_user.id

      find_by(github_id: github_user.id)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/shipit/github_authentication_controller.rb (L30-34)
```ruby
    def sign_in_github(auth)
      user = User.find_or_create_from_github(auth.extra.raw_info)
      user.update(github_access_token: auth.credentials.token)
      user.id
    end
```
