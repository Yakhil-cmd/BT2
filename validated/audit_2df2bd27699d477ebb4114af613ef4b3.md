### Title
Cross-organization webhook forgery in `MembershipHandler#process` allows escalation into privileged `Shipit.github_teams` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
The `membership` webhook is authenticated only by verifying that the raw request body's HMAC matches the webhook secret configured for the organization named in `params['organization']['login']` (or `params['repository']['owner']['login']`). Nothing after that verifies that the `team.id` referenced inside the JSON body actually belongs to that same authenticated organization, so an attacker who owns any org with a configured GitHub App in Shipit can forge a `membership`/`added` webhook naming a completely unrelated, privileged team and add their own GitHub login to it.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't:
`organization_that_authenticated_the_signature (params.organization.login, owned/controlled by attacker) == organization_that_actually_owns_the_referenced_team (Team#organization for the row matched by params.team.id)`.

`WebhooksController#verify_signature` resolves the signing organization from the payload itself and verifies the HMAC using that organization's own `webhook_secret`: [1](#0-0) [2](#0-1) 

This only proves "someone who knows organization X's webhook secret sent this exact body." Since the attacker legitimately owns org X and has configured a GitHub App for it in Shipit (stated precondition), the attacker knows X's `webhook_secret` and can compute a valid signature for **any** JSON content they choose — GitHub does not need to be involved at all; the attacker can POST directly to `/webhooks`.

`MembershipHandler#process` then trusts the attacker-supplied `team.id` unconditionally: [3](#0-2) 

`find_or_create_team!` looks the `Team` row up (or creates it) purely by `github_id`, with no check that the team's `organization` matches the org that authenticated the request: [4](#0-3) 

If a `Team` row with that `github_id` already exists — which is exactly the case for teams listed in `Shipit.github_teams`, since they must be provisioned/known to Shipit beforehand — `find_or_create_by!` simply returns the existing record and skips the `organization:`-setting block entirely. The handler then calls: [5](#0-4) 
which appends `member` (created via `User.find_or_create_by_login!(params.member.login)`, using the attacker's real GitHub login) to `members` regardless of which organization actually authenticated the request.

Once membership is written, `User#authorized?` checks only team IDs, not organizations: [6](#0-5) 
and `force_github_authentication` grants access based solely on `authorized?`: [7](#0-6) 

No existing guard closes this gap: `verify_signature` authenticates only the org named in the payload, not the org owning the referenced team; `ExplicitParameters` only validates types/presence, not cross-field/org consistency; `drop_unhandled_event` only filters unknown event types.

**Exploit flow:**
1. Attacker owns org `evil-org`, which has its own GitHub App configured in Shipit (thus attacker knows `evil-org`'s `webhook_secret`).
2. Attacker computes `sha1=HMAC(webhook_secret_evil_org, body)` for a forged JSON body:
   `{"action":"added","team":{"id":<github_id of Shipit.github_teams[0]>,"name":"x","slug":"x","url":"x"},"organization":{"login":"evil-org"},"member":{"login":"attacker-real-login"}}`
3. Attacker POSTs this to `/webhooks` with header `X-Github-Event: membership` and the computed `X-Hub-Signature`.
4. `verify_signature` succeeds (it only checks the signature against `evil-org`'s secret, which matches).
5. `MembershipHandler#process` finds the pre-existing privileged `Team` by `github_id` (belonging to some other, real org) and adds the attacker's real GitHub user to it.
6. Attacker logs into Shipit via normal OmniAuth with their real GitHub account; `User#authorized?` now returns `true` because their user row has a `Membership` in a team listed in `Shipit.github_teams`.

### Impact Explanation
This grants the attacker's real GitHub account membership in a Shipit-privileged team without any actual GitHub-side membership check, i.e., escalation into `Shipit.github_teams` authorization — matching the "High" impact category verbatim ("escalation into `Shipit.github_teams` authorization"). Once authorized, the attacker gains full application access gated by `force_github_authentication`, including whatever stacks/deploys/rollbacks that authorization level exposes across all repositories/tenants managed by this Shipit instance, not just their own org's. The attack is fully repeatable (any number of memberships can be forged, including into every team the attacker discovers `github_id`s for) as long as the attacker retains any org with a configured GitHub App.

### Likelihood Explanation
Preconditions are exactly as stated: attacker owns any GitHub org that has been configured with a GitHub App in this Shipit instance (a common self-service situation for a multi-tenant Shipit install), and needs to know (or brute-force/guess/discover, e.g. via a rake task output, prior legitimate webhook, or Shipit UI team listing) the numeric `github_id` of a team already present in `Shipit.github_teams`. No Shipit secrets, GitHub App private keys, or victim-org webhook secrets are required — only the attacker's own webhook secret, which they legitimately possess. This is a low-cost, fully repeatable attack requiring only HTTP requests.

### Recommendation
In `MembershipHandler#process` (and analogous handlers), verify that the organization authenticated by `verify_signature`/derived from the request equals the `Team#organization` of the team being looked up before mutating membership; reject (or no-op) the event if `params.organization.login` doesn't match the existing `Team#organization`. More generally, `WebhooksController#verify_signature` should bind the verified organization into the handler context so handlers can assert `payload_organization == resource.organization` for any object referenced by ID in the payload, rather than trusting attacker-controlled IDs across organizational boundaries.

### Proof of Concept
Minitest plan (no live GitHub, uses `Shipit.github_teams` config and existing test signing helpers):
```ruby
test "membership webhook cannot add a member to a team belonging to a different organization" do
  # Arrange: create a privileged team belonging to `victim-org`, already listed in Shipit.github_teams
  victim_team = shipit_teams(:some_configured_team) # organization == 'victim-org', github_id == 4242
  assert_includes Shipit.github_teams.map(&:id), victim_team.id

  # Attacker's own org has its own configured webhook secret
  attacker_org = 'evil-org'
  payload = {
    action: 'added',
    team: { id: victim_team.github_id, name: 'x', slug: 'x', url: 'https://x' },
    organization: { login: attacker_org },
    member: { login: 'attacker-real-login' }
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', Shipit.github(organization: attacker_org).send(:webhook_secret), payload)}"

  post shipit.webhooks_path, params: payload,
       headers: { 'X-Github-Event' => 'membership', 'X-Hub-Signature' => signature, 'Content-Type' => 'application/json' }

  assert_response :ok

  attacker_user = Shipit::User.find_by!(login: 'attacker-real-login')

  # Assert the broken binding: attacker org != victim team's organization, yet membership was written
  refute_equal attacker_org, victim_team.organization
  assert_includes victim_team.reload.members, attacker_user

  # Prove downstream authorization bypass
  attacker_user.update!(name: 'Attacker') # satisfy validation
  post '/session', params: {} # simulate omniauth login stub setting session[:user_id]
  # or directly:
  # session[:user_id] = attacker_user.id
  assert attacker_user.authorized?, "attacker should not be authorized via a forged cross-org webhook"
end
```
This demonstrates both sides of the equality explicitly (`attacker_org` vs `victim_team.organization`) diverging while membership and authorization are still granted, confirming the binding failure.

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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
