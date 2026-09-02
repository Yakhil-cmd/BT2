### Title
Cross-organization team hijack via `membership` webhook (`find_or_create_team!` trusts attacker-controlled `team.id`) - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` looks up (or creates) a `Team` solely by the attacker-supplied `team.id` (mapped to `github_id`), with no check that the organization whose `webhook_secret` verified the request is the actual owner of that `github_id`. An attacker who controls any GitHub organization can therefore send a signed `membership` webhook naming an arbitrary numeric `team.id` and add themselves as a member of whatever pre-existing `Team` row in Shipit's database happens to have that `github_id`, including a team listed in `Shipit.github_teams`.

### Finding Description
The broken binding: the question's required invariant is
`org_that_signed_webhook == team.organization (on the Team row) == real_github_owner_of(github_id)`.

Tracing the code shows this is never enforced:

- `WebhooksController#verify_signature` resolves the org used for signature verification from `repository_owner`, which for a `membership` payload falls back to `params.dig('organization', 'login')` [1](#0-0) [2](#0-1) . This only proves the request was signed by *some* org the attacker legitimately controls — it says nothing about the `team.id` field also present in the payload.
- `MembershipHandler#find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id)`, where `params.team.id` is an attacker-controlled integer validated only for type (`Integer`), not ownership [3](#0-2) [4](#0-3) . If a `Team` row with that `github_id` already exists (created earlier by the legitimate org's own sync, e.g. via `Team.find_or_create_by_handle` or `Shipit.github_teams`), `find_or_create_by!` returns the *existing* row without running the initializer block — so `team.organization` is left as the legitimate org, but the record itself is now the one being mutated.
- `process` then calls `team.add_member(member)` for `action == 'added'`, appending the attacker's own `User` (created from `params.member.login`, also fully attacker-controlled) to that team's `members` [5](#0-4) [6](#0-5) .
- `User#authorized?` checks membership by the `Team`'s primary key `id`, not `github_id`: `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) . So if the hijacked row's `id` is one of the configured `Shipit.github_teams`, the attacker becomes authorized.

Attacker request: POST `/webhooks` with header `X-Github-Event: membership`, body `{"action":"added","organization":{"login":"attacker-org"},"team":{"id": <victim_github_id>, "name":"x","slug":"x","url":"x"},"member":{"login":"attacker-login"}}`, signed with `attacker-org`'s own valid `webhook_secret` (`X-Hub-Signature`). `verify_signature` succeeds because it only checks `attacker-org`'s secret against `attacker-org`'s own payload — it never checks that `attacker-org` actually owns team id `victim_github_id`.

None of the existing guards catch this: `verify_signature` only binds the signature to `organization.login`, not to `team.id`; the `ExplicitParameters` schema in `MembershipHandler` only enforces types; there is no `require_permission!` or ownership check inside `find_or_create_team!`; and `User#authorized?` trusts primary-key team membership without re-validating provenance.

### Impact Explanation
A successful request causes the attacker's GitHub login to be added as a `Membership` on a `Team` record that belongs (by `id`) to `Shipit.github_teams`, without ever authenticating against that team's real organization. This directly escalates the attacker into `authorized?` == `true`, granting them full access to the Shipit UI/API as an "authorized" user — session-gated actions like triggering deploys, rollbacks, or viewing/mutating stacks become available. This is repeatable per victim `github_id`/team and is not confined to the attacker's own org's data, so it crosses tenant boundaries. This matches the "High - escalation into `Shipit.github_teams` authorization" impact category.

### Likelihood Explanation
Preconditions: attacker owns/administers at least one GitHub organization with Shipit installed/configured (so they have a valid `webhook_secret` for signing), and a `Team` row for the target privileged team must already exist in Shipit's database with a `github_id` the attacker can guess or discover (GitHub team ids are typically discoverable via the GitHub API for teams the attacker can query, or leaked via other webhook/API responses). No Shipit secrets, session, or special role are required — only ordinary control of a GitHub org's webhook configuration, which is explicitly within the attacker's allowed capabilities per the rules. The attack is a single crafted HTTP POST, fully repeatable.

### Recommendation
Bind the team lookup/creation and mutation to the organization that actually signed the webhook: verify (via the GitHub API using the credentials tied to `repository_owner`/`organization.login`, or by checking `team.organization == params.organization.login` on the existing record) that the found/created `Team#organization` matches the signing organization before calling `add_member`/`delete`. Reject or no-op the webhook if an existing `Team` with the given `github_id` has an `organization` different from `params.organization.login`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":membership cannot be used to join a team belonging to another organization" do
  victim_team = Shipit::Team.create!(
    github_id: 42,
    organization: 'victim-org',
    slug: 'privileged',
    name: 'Privileged',
    api_url: 'https://api.github.com/teams/42'
  )
  Shipit.stubs(:github_teams).returns([victim_team])

  attacker = shipit_users(:walrus) # stand-in "attacker" user, currently unauthorized
  refute victim_team.organization == 'attacker-org' # binding: signing org != team owner org
  refute attacker.authorized?

  @request.headers['X-Github-Event'] = 'membership'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulate attacker-org's own valid webhook_secret
  post :create, as: :json, body: {
    action: 'added',
    organization: { login: 'attacker-org' },
    team: { id: 42, name: 'irrelevant', slug: 'irrelevant', url: 'irrelevant' },
    member: { login: attacker.login }
  }.to_json
  assert_response :ok

  victim_team.reload
  assert_includes victim_team.members, attacker      # attacker added to victim's privileged team
  assert attacker.reload.authorized?                 # and is now authorized in Shipit
end
```
This demonstrates that the equality `organization_that_signed_webhook == real_owner_of(team.github_id)` is not enforced, and that violating it grants unauthorized `Shipit.github_teams` membership.

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
