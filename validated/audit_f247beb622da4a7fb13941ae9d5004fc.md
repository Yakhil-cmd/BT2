### Title
`MembershipHandler#process` binds `Membership` records to any pre-existing Shipit `User` by login string alone, and `Team` lookup by `github_id` is not scoped to the verified organization - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::MembershipHandler#process` resolves the target `User` via `User.find_or_create_by_login!(params.member.login)` [1](#0-0)  and the target `Team` via `Team.find_or_create_by!(github_id: params.team.id)` [2](#0-1) . Neither lookup is cross-checked against the organization whose webhook secret actually authenticated the request, so an attacker who controls a legitimately-configured (but low-privilege) GitHub organization can forge a `membership` "added"/"removed" event that mutates the `Membership` of an arbitrary, already-existing Shipit `User` against an arbitrary, already-existing `Team` (including entries in `Shipit.github_teams`).

### Finding Description
The broken binding, stated as an equality: `Membership.user` should equal "the GitHub identity that authenticated this specific webhook event, verified as a real member action inside `params.organization.login`'s GitHub team `params.team.id`" — but in the code it is set to whatever `User` row happens to match `login: params.member.login` **and** whatever `Team` row happens to match `github_id: params.team.id`, both attacker-controlled fields, with no re-verification against GitHub.

Code path:
1. `WebhooksController#verify_signature` selects the GitHub App config by `repository_owner` (`params.dig('repository','owner','login')` or `params.dig('organization','login')`) and validates the HMAC signature using **that organization's** `webhook_secret` [3](#0-2) . This only proves the request came from *some* organization Shipit trusts (in a multi-tenant deployment, this can be the attacker's own onboarded/low-privilege org) — it says nothing about the `team.id` or `member.login` values inside the JSON body.
2. `MembershipHandler#process` then does:
   - `team = find_or_create_team!` → `Team.find_or_create_by!(github_id: params.team.id) { |team| team.github_team = params.team; team.organization = params.organization.login }` [2](#0-1) . The `organization` assignment only runs **on creation**; if a `Team` row with that `github_id` already exists (e.g. a real entry from `Shipit.github_teams`), it is returned unchanged, regardless of which organization's signature verified the request.
   - `member = User.find_or_create_by_login!(params.member.login)` → `find_or_create_by!(login:) { |user| user.github_user = Shipit.github.api.user(login) }` [4](#0-3) . If a `User` row with that `login` already exists, it is returned as-is; the GitHub API call to `Shipit.github.api.user(login)` only executes inside the create block, i.e. **only when the row doesn't already exist**. No `github_id` comparison against the organization's member list is ever performed for existing users.
   - `team.add_member(member)` unconditionally creates the `Membership` row [5](#0-4) .

Existing repo tests already demonstrate this exact behavior with no live GitHub confirmation call: `test ":membership can append an user membership"` posts `member: { login: 'bob' }` (an existing fixture user) and asserts a `Membership` is created, without stubbing any GitHub API confirmation [6](#0-5) .

None of the listed guards prevent this: `verify_signature` only authenticates the sending organization, not the JSON payload's internal references to `team.id`/`member.login`; `ExplicitParameters` (`params do ... end`) only validates types/presence, not cross-organization consistency [7](#0-6) ; `User#authorized?` and `require_permission!` are downstream consumers of `Membership`, not producers, so they don't stop the forged write.

### Impact Explanation
An attacker who administers any organization onboarded to a multi-tenant Shipit instance (with its own valid `webhook_secret`) can:
- Add an arbitrary, already-existing Shipit `User` (identified only by public GitHub login) to any `Team` whose `github_id` is known or guessable — including teams listed in `Shipit.github_teams`, escalating that user's (and thus anyone impersonating that identity's actions) `authorized?` status via `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [8](#0-7) .
- Or remove an arbitrary existing operator from a privileged team (`action: 'removed'`), silently deauthorizing them.

This is repeatable against any `login`/`team.id` pair and is not scoped to the attacker's own tenant, so it can escalate into `Shipit.github_teams` authorization — matching the "High" severity bucket defined in the rules (escalation into `Shipit.github_teams` authorization).

### Likelihood Explanation
Preconditions: the deployment must be multi-tenant (more than one organization/App config in `secrets.github`), and the attacker must control one such organization with a real, distinct `webhook_secret` (achievable simply by being an admin of any org onboarded to the Shipit instance — no Shipit session or Shipit secret needed, only the ability to configure/simulate a webhook to their own trusted GitHub App/org, or to directly POST a correctly-signed payload to `/webhooks`). The attacker needs to know or guess the target `team.id` (GitHub team numeric ID, which is not secret and can leak via GitHub org member/API pages or Shipit's own UI showing `handle`s) and the target `login` (a public GitHub username of a real operator). No GitHub API confirmation is required to succeed against pre-existing rows. This is directly demonstrable via minitest with no live GitHub calls.

### Recommendation
- In `MembershipHandler#process`, revalidate the resolved `member` and `team` against the organization that authenticated the webhook: e.g. call GitHub with the verified org's API client to confirm `params.member.login` is currently a member of `params.team.id` before mutating `Membership`, or at minimum verify `team.organization == params.organization.login` and reject processing if it doesn't match the organization used for signature verification.
- In `User.find_or_create_by_login!`, when reusing an existing record, still perform a GitHub lookup (`Shipit.github.api.user(login)`) and compare `github_id` to the existing record's `github_id`, rejecting the operation (or refusing to trust the payload) on mismatch/absence of confirmation.
- Scope `Team.find_or_create_by!` lookups by `(github_id, organization)` rather than `github_id` alone, and reject events whose `params.organization.login` doesn't match the `repository_owner`/signing organization used by `verify_signature`.

### Proof of Concept
Minitest plan (extends `test/controllers/webhooks_controller_test.rb` pattern, no live GitHub call stubbed):
```ruby
test ":membership from a forged 'own org' payload attaches an existing privileged user to a Shipit.github_teams team without GitHub confirmation" do
  operator = shipit_users(:walrus) # pre-existing, already-privileged User fixture
  target_team = shipit_teams(:shopify_developers) # a team whose id is in Shipit.github_teams

  # Binding under test (BEFORE): Membership.exists?(user: operator, team: target_team) == false
  refute Membership.exists?(user: operator, team: target_team)

  @request.headers['X-Github-Event'] = 'membership'
  # Signature is computed/valid for the attacker's own org's webhook_secret,
  # simulating Shipit.github(organization: 'attacker-org').verify_webhook_signature(...) => true
  Shipit::User.any_instance.expects(:github_api).never
  Shipit.github.api.expects(:user).never # No GitHub confirmation call is made for an existing user

  post :create, body: {
    action: 'added',
    team: { id: target_team.github_id, name: target_team.name, slug: target_team.slug, url: target_team.api_url },
    organization: { login: 'attacker-org' },
    member: { login: operator.login },
    repository: { owner: { login: 'attacker-org' } }
  }.to_json, as: :json

  assert_response :ok
  # Binding under test (AFTER): Membership now exists purely from the forged login string,
  # with no GitHub API confirmation call ever invoked.
  assert Membership.exists?(user: operator, team: target_team)
end
```
This proves the equality "`Membership.user` == identity authenticated by this webhook" is false: the `Membership` is created solely because `params.member.login` textually matches an existing operator's login, with the request only authenticated for a different (attacker-controlled) organization and no GitHub API call ever confirming the claimed membership.

### Citations

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L159-165)
```ruby
    test ":membership can append an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'bob' }).to_json, as: :json
        assert_response :ok
      end
    end
```
