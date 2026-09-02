### Title
Cross-organization team membership forgery via `MembershipHandler#find_or_create_team!` github_id lookup - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::MembershipHandler#find_or_create_team!` resolves the target `Team` purely by the attacker-controlled numeric `team.id` field, without ever checking that the webhook's cryptographically verified originating organization (`repository_owner`, used to select which `webhook_secret` validates the signature) actually owns that `Team`. This lets an attacker who legitimately controls (and has a valid webhook secret for) one GitHub organization registered in Shipit forge a `membership` "added" event that adds an arbitrary GitHub login to a `Team` belonging to a completely unrelated organization, as long as that team's numeric `github_id` is known/guessed.

### Finding Description
The intended binding is: `verified_signature_organization (repository_owner) == team.organization` for the `Team` a membership webhook is allowed to mutate. This is enforced only when a `Team` row doesn't already exist: [1](#0-0) 

`Team.find_or_create_by!(github_id: params.team.id)` looks the team up **solely by numeric `github_id`**; the block that assigns `team.organization = params.organization.login` only runs on the create path (ActiveRecord semantics), so if a `Team` with that `github_id` already exists (e.g. one of the operator's `Shipit.github_teams`, previously synced via `Team.find_or_create_by_handle`), the lookup returns that pre-existing record untouched — regardless of which organization the verified webhook actually came from.

`WebhooksController#verify_signature` selects the HMAC secret to check against using `repository_owner`, which for a `membership` event (no `repository` key present) falls back to `params.dig('organization', 'login')` — a value fully controlled by the sender's JSON body: [2](#0-1) [3](#0-2) 

So an attacker who legitimately administers Organization A (registered in Shipit's multi-org GitHub config with their own known `webhook_secret`) can send:
```
POST /webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=<HMAC using Org A's real webhook_secret>
{
  "action": "added",
  "organization": {"login": "org-a"},
  "team": {"id": <github_id of an existing Shipit.github_teams team belonging to Org B>, "name": "...", "slug": "...", "url": "..."},
  "member": {"login": "<attacker's real GitHub login>"}
}
```
Signature verification succeeds (it's checked against Org A's real secret, which the attacker legitimately possesses). `MembershipHandler#process` then finds the pre-existing Org B `Team` by `github_id` and calls `team.add_member(member)`, where `member = User.find_or_create_by_login!(params.member.login)`: [4](#0-3) 

This method calls the live GitHub API (`Shipit.github.api.user(login)`) and stores the *real* `github_id` for that login, so a subsequent, entirely legitimate OAuth login by the attacker as that same GitHub account resolves to the same `User` row (`find_from_github` matches by `github_id`): [5](#0-4) 

`User#authorized?` then evaluates true because the forged `Membership` links the attacker's real account to an `id` inside `Shipit.github_teams`: [6](#0-5) 

Existing guards do not catch this: `verify_signature` only proves "this payload came from an org whose secret matches," never "this payload's team belongs to that org"; `drop_unhandled_event` and the `ExplicitParameters` schema on `MembershipHandler` only validate shape/type, not organization/team ownership; `force_github_authentication`/`User#authorized?` trust the `Membership` table's contents unconditionally.

### Impact Explanation
Once `authorized?`, the attacker is treated as a full member of the Shipit install (this app has no per-team stack isolation — `Api::BaseController#stacks` returns `Stack.all` unless an `ApiClient` is explicitly scoped to a `stack_id`; permission checks are purely `ApiClient`-level, per `require_permission :read, :stack` in `Api::OutputsController`). The attacker can log in through the normal web UI, create an `ApiClient` with `read:stack` and no `stack_id` restriction, and then call `GET /api/stacks/:id/tasks/:task_id/output` (`Api::OutputsController#show`) to read `task.chunk_output` for any stack belonging to any organization hosted on the same Shipit instance — including ones they never had any legitimate relationship with. This is repeatable for any `github_id` the attacker can discover, matches "High - escalation into Shipit.github_teams authorization," and cascades into "Critical - exfiltration of deploy/task output" once combined with the pre-existing (by-design) lack of per-org stack scoping in the API.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured with more than one GitHub organization (multi-org `github:` config) — a documented, supported configuration; (2) the attacker legitimately administering at least one of those orgs (low cost — they can be a completely unrelated organization owner); (3) knowledge/guess of the target team's numeric GitHub `github_id`, which is not secret but also not always trivially discoverable without some org visibility. Given (3), likelihood is Medium rather than trivial, but the attack requires no Shipit secrets, no session, and no prior Shipit access — purely webhook crafting.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that the resolved `Team#organization` matches the verified webhook's organization (`params.organization.login`) before applying any membership mutation, e.g. raise/drop the event if `team.persisted? && team.organization != params.organization.login`. Additionally, scope the `Team.find_or_create_by!` lookup by the composite of `github_id` and `organization` rather than `github_id` alone.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, extended):
```ruby
test "membership webhook cannot grant access to a team owned by a different organization" do
  target_team = shipit_teams(:shopify_developers) # organization == 'shopify', part of Shipit.github_teams
  Shipit.stubs(:github_teams).returns([target_team])

  # Attacker legitimately controls "attacker-org" with its own webhook secret in Shipit's multi-org config
  GithubApp.any_instance.stubs(:verify_webhook_signature).returns(true) # simulate valid sig for attacker-org

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    organization: { login: 'attacker-org' },
    team: { id: target_team.github_id, name: target_team.name, slug: target_team.slug, url: target_team.api_url },
    member: { login: 'attacker_login' }
  }.to_json

  assert_no_difference -> { Membership.where(team_id: target_team.id).count }, "cross-org membership should not be created" do
    post :create, body: payload, as: :json
  end
end
```
Assert both sides of the binding: `team.organization` (== `'shopify'`) must equal the webhook's verified organization (`'attacker-org'`) before mutating `Membership`; currently they diverge and the record is still written, which the fixed code must reject.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/controllers/shipit/github_authentication_controller.rb (L30-34)
```ruby
    def sign_in_github(auth)
      user = User.find_or_create_from_github(auth.extra.raw_info)
      user.update(github_access_token: auth.credentials.token)
      user.id
    end
```
