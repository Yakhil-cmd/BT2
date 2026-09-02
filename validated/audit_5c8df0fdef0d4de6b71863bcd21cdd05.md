### Title
`Membership` has no organization-binding validation, allowing a foreign-organization webhook to attach members to another organization's `Team` - ([File: app/models/shipit/membership.rb])

### Summary
`Shipit::Membership` only validates `user_id` uniqueness scoped to `team_id`; it has no validation that the membership's `team.organization` matches the organization that authenticated the webhook which created it. Because `Shipit::Webhooks::Handlers::MembershipHandler#find_or_create_team!` looks up an existing `Team` by `github_id` alone (ignoring `params.organization.login` for any team that already exists), a `membership` webhook signed by one configured GitHub organization can attach an arbitrary member to a `Team` that belongs to a different organization, and the resulting `Membership` row passes the model's only validation unchanged.

### Finding Description
The binding the question asks about is: for every `Membership` row, `membership.team.organization == organization_that_signed_the_webhook_which_created_it`.

Trace:
- `Shipit::WebhooksController#verify_signature` picks the `GitHubApp` used for HMAC verification from `repository_owner`, which for membership payloads falls back to `params.dig('organization', 'login')`: [1](#0-0) [2](#0-1) . This only proves the payload was signed by *some* configured organization's secret — the one the attacker chose in the `organization.login` field of their own payload.
- `MembershipHandler#find_or_create_team!` resolves the target `Team` by `github_id` only: `Team.find_or_create_by!(github_id: params.team.id) { |team| team.github_team = params.team; team.organization = params.organization.login }` [3](#0-2) . The `team.organization = params.organization.login` assignment only executes inside the `find_or_create_by!` block, i.e. **only when a new record is being created**. When an existing `Team` matches `github_id`, it is returned as-is, and its stored `organization` is never re-checked against the webhook's claimed organization.
- `process` then does `team.add_member(member)`, appending a `User` (itself resolved purely from `params.member.login`, attacker-controlled) to that `Team`'s `members` through `Membership` [4](#0-3) .
- The only guard on the created `Membership` row is: `validates :user_id, uniqueness: { scope: :team_id }` [5](#0-4) . Nothing checks `team.organization` against any webhook-derived value, so a `Membership` built this way is `valid?` and indistinguishable from a legitimate one.
- `User#authorized?` grants access based purely on presence in `Shipit.github_teams` via this same `teams`/`memberships` association: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) .

Exploit flow: an attacker who controls a GitHub organization/App that is one of Shipit's configured organizations (per `docs/setup.md`'s multi-org config) sends `POST /webhooks` with `X-Github-Event: membership`, a valid signature for their own org's `webhook_secret`, and a payload naming `organization.login` = their own org, but `team.id` = the numeric `github_id` of an existing, unrelated `Team` (e.g. one referenced in `Shipit.github_teams`) belonging to a victim organization, and `member.login` = their own GitHub login. `find_or_create_by!(github_id: ...)` matches the victim's pre-existing `Team` row, `team.add_member` creates a `Membership` linking the attacker's `User` to the victim's `Team`, and the model happily validates it since it only checks per-team uniqueness.

### Impact Explanation
This is a cross-tenant authorization escalation: an attacker-controlled `User` can be injected as a member of any pre-existing `Team` whose GitHub `github_id` the attacker learns or guesses, including a `Team` that is part of `Shipit.github_teams`, thereby satisfying `User#authorized?` and gaining application-wide access to a Shipit instance meant for a different organization — matching the "High: escalation into `Shipit.github_teams` authorization" category. The `Membership` model provides zero compensating control; the row created is stored as an ordinary, valid membership.

### Likelihood Explanation
Requires: (1) Shipit configured with more than one GitHub organization (`docs/setup.md`'s "Using Multiple GitHub Applications" section), and (2) the attacker owning/controlling one of those configured organizations so they can produce a validly signed `membership` webhook. Given those preconditions — realistic for any Shipit instance onboarding multiple external orgs — the attack costs only a single crafted HTTP POST with a correct HMAC signature for the attacker's own org, and the target `team.id` (a GitHub team numeric ID, often discoverable via the public GitHub API). It is repeatable against any team whose `github_id` is known, and requires no Shipit session, API token, or victim-org secret.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify (and reject if mismatched) that the resolved `Team#organization` equals `params.organization.login` before performing `add_member`/`delete`, or scope the `find_or_create_by!` lookup by `github_id` **and** `organization`. Additionally, add a model-level validation on `Membership`/`Team` ensuring a membership can only be created when the acting webhook's organization matches `team.organization`, so the model is not solely reliant on handler-level correctness.

### Proof of Concept
```ruby
# test/models/membership_test.rb (illustrative addition)
test "model does not validate membership against team's organization" do
  shopify_team = shipit_teams(:shopify_developers) # team.organization == 'shopify'

  # Simulate a user created via a webhook forged from an unrelated org
  attacker_user = User.create!(login: 'attacker', github_id: 999_999)

  membership = Membership.new(user: attacker_user, team: shopify_team)

  assert_equal 'shopify', shopify_team.organization
  # No validation ties membership.team.organization to the org that
  # actually authenticated the webhook that produced attacker_user/this row.
  assert membership.valid? # passes: only uniqueness(scope: team_id) is checked
end
```
```ruby
# test/controllers/webhooks_controller_test.rb (illustrative addition)
test "membership webhook signed by one org can add a member to another org's pre-existing team" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id known
  @request.headers['X-Github-Event'] = 'membership'

  payload = {
    action: 'added',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: 'attacker-org' },     # signs with attacker-org's own secret
    member: { login: 'attacker' }
  }.to_json

  Shipit.github(organization: 'attacker-org').stubs(:verify_webhook_signature).returns(true)

  assert_difference -> { Membership.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end

  assert_includes victim_team.reload.members.map(&:login), 'attacker'
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

**File:** app/models/shipit/membership.rb (L4-9)
```ruby
  class Membership < Record
    belongs_to :team, required: true
    belongs_to :user, required: true

    validates :user_id, uniqueness: { scope: :team_id }
  end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
