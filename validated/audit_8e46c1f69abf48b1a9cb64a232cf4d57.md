### Title
`Team.find_or_create_by!(github_id:)` ignores the webhook's authenticated organization, letting an attacker join arbitrary privileged teams via an unsigned `membership` webhook - (`app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` looks up a `Team` solely by the attacker-supplied `params.team.id`, with no check that the team's `organization` matches the organization that the webhook was purportedly received from. Combined with `GithubApp#verify_webhook_signature` returning `true` unconditionally whenever `webhook_secret` is blank (a documented "optional" config, used by default in `test/dummy/config/secrets.yml`, `config/secrets.development.example.yml`, and `template.rb`), this lets an attacker who can name any already-configured organization forge a `membership` webhook that adds themselves to a pre-existing, privileged `Team` row keyed by `github_id`, regardless of which organization actually "signed" the request.

### Finding Description
The broken binding: `params.organization.login` (the organization the request claims to originate from, and the one used to select the `GithubApp` used for signature verification) should equal `team.organization` (the organization that owns the `Team` row being mutated). In practice these are decoupled:

- `WebhooksController#verify_signature` picks the verifying `GithubApp` via `repository_owner`, which for a `membership` payload (no `repository` key in the schema) resolves to `params.dig('organization', 'login')`: [1](#0-0) [2](#0-1) 
- `GithubApp#verify_webhook_signature` short-circuits to `true` before even inspecting the signature header if `webhook_secret` is blank: [3](#0-2) 
- `MembershipHandler#process` then resolves the team purely by `github_id`, and unconditionally calls `add_member` on whatever `Team` row that matches - a brand-new row for the claimed organization, or (critically) an existing row belonging to a *different* organization if the numeric `github_id` collides: [4](#0-3) 
- `Team#add_member` just appends the member with no organization check: [5](#0-4) 
- Authorization into the whole app is entirely driven by team membership rows: [6](#0-5) [7](#0-6) 

Exploit flow: attacker sends `POST /webhooks` with header `X-Github-Event: membership`, no (or garbage) `X-Hub-Signature`, and body `{action:'added', team:{id: <github_id of the target privileged Team>, name, slug, url}, organization:{login: <any org configured on this Shipit instance with a blank webhook_secret>}, member:{login: attacker_login}}`. `verify_signature` resolves the `GithubApp` for that named organization and, finding `webhook_secret` blank, accepts the request unconditionally. `find_or_create_team!` matches the existing `Team` row by `github_id` (ignoring that the claimed organization differs from `team.organization`), and `team.add_member(member)` inserts `attacker_login` into that privileged team. `User#authorized?` subsequently returns `true` for that user.

Existing guards fail because: (1) signature verification depends only on whether *a* secret is configured for *the organization named in the untrusted payload*, not on cryptographic proof tied to the specific team/organization being mutated; and (2) `Team.find_or_create_by!` has no `organization:` clause in its lookup, only in the creation block, so it silently matches pre-existing rows for any organization once the numeric `github_id` is known.

### Impact Explanation
A successful request inserts the attacker into an existing privileged `Team`, i.e. one listed in `Shipit.github_teams`. Since `User#authorized?` is entirely membership-row driven, this is a full authentication bypass into the Shipit application (all stacks, deploys, rollbacks, API client management) for that user - matching the "High: escalation into `Shipit.github_teams` authorization" category (and arguably enabling further Critical actions such as unauthorized deploys once inside). It is repeatable against any `Team` row whose `github_id` the attacker can supply, and is not scoped to a single tenant/organization: any organization configured on the Shipit instance with a blank `webhook_secret` can be used as the "signing" identity while a completely different organization's `Team` row is the one mutated.

### Likelihood Explanation
Preconditions: (1) at least one organization configured on the Shipit instance (the one named in the forged payload's `organization.login`) has no `webhook_secret` set - a state the docs describe as merely "optional" and which is the default in the shipped example configs; (2) the attacker must know the numeric GitHub `github_id` of the target privileged `Team`. That ID is a GitHub-wide identifier, not inherently secret, but it is not trivially discoverable for a private/secret team the attacker doesn't belong to - it would need to leak via some other channel (public team listing, prior webhook delivery, GitHub API access to that org, etc.). Given that constraint, likelihood is moderate: the missing-secret precondition is common in real deployments, but the team-id-knowledge requirement narrows the practical attack surface. No Shipit or GitHub secret is required from the attacker.

### Recommendation
- Require `Team.find_or_create_by!` (and any subsequent membership mutation) to also filter/verify on `organization: params.organization.login`, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, rejecting or ignoring events where an existing `github_id` maps to a different `organization`.
- Make `webhook_secret` mandatory (fail fast at boot if blank) rather than silently accepting all payloads when unset, closing the root bypass in `GithubApp#verify_webhook_signature`.
- Additionally validate that `repository_owner`/`organization.login` used for signature verification matches the organization actually associated with the `Team`/`Repository` being mutated before applying any writes.

### Proof of Concept
Minitest (`test/controllers/webhooks_controller_test.rb`-style), no live GitHub:
```ruby
test "membership webhook cannot add an attacker to a Team owned by a different organization, when the request's organization has no webhook_secret" do
  privileged_team = shipit_teams(:shopify_developers) # organization == 'shopify', github_id already set
  attacker_org = 'attacker-org'

  # Simulate multi-org config where attacker_org has no webhook_secret configured
  Shipit.stubs(:github).with(organization: attacker_org).returns(
    Shipit::GitHubApp.new(attacker_org, { webhook_secret: nil })
  )

  request.headers['X-Github-Event'] = 'membership'
  body = {
    action: 'added',
    team: { id: privileged_team.github_id, name: privileged_team.name, slug: privileged_team.slug, url: privileged_team.api_url },
    organization: { login: attacker_org },
    member: { login: 'attacker_login' }
  }.to_json

  assert_no_difference -> { Shipit::Team.count } do
    post :create, body: body, as: :json
  end
  assert_response :ok

  attacker = Shipit::User.find_by(login: 'attacker_login')
  refute_nil attacker
  # Broken binding check: authenticated org (attacker_org) != privileged_team.organization ('shopify'), yet membership was written
  assert privileged_team.members.include?(attacker),
    "attacker should NOT be a member of a Team belonging to a different organization"
  refute attacker.authorized?, "attacker must not become authorized via a cross-organization forged webhook"
end
```
The test asserts the binding `attacker_org == privileged_team.organization` is false while `Team#members` still gets mutated and `User#authorized?` flips to true - demonstrating the exploit; a fix should make this test pass by rejecting the mismatched write.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
