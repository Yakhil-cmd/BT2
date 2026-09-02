### Title
Blank `webhook_secret` causes `GitHubApp#verify_webhook_signature` to fail open, allowing forged `membership` webhooks to grant attacker-controlled `Shipit::Team` membership and bypass `User#authorized?` - (File: lib/shipit/github_app.rb)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` whenever no `webhook_secret` is configured for the organization, meaning any organization onboarded to Shipit without an explicit webhook secret accepts unsigned, forged webhooks. Combined with `MembershipHandler`, which blindly trusts the JSON payload to create/attach a `User` to a `Team` scoped by `params.organization.login`, an attacker can forge a `membership` event to insert themselves into any `Shipit::Team` referenced in `Shipit.github_teams`, flipping `User#authorized?` to `true` without ever being a real GitHub org member.

### Finding Description
The binding claimed is: *the organization whose signature was verified == the organization whose `Team`/`Membership` rows are mutated*. Tracing the code:

- `WebhooksController#verify_signature` resolves `repository_owner` from the same JSON body (`params.dig('repository','owner','login') || params.dig('organization','login')`) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
- `MembershipHandler#find_or_create_team!` uses `params.organization.login` (the exact same JSON field) to scope the `Team`. [3](#0-2) 

For the `membership` event specifically these two values are identical (no `repository.full_name` vs `owner` divergence exists here, since the payload has no `repository` key), so the cross-org mismatch alleged in the question does not reproduce for this event type.

The actual break is upstream, in `verify_webhook_signature` itself:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [4](#0-3) 
If `victim-org`'s `webhook_secret` is blank/unset in configuration, signature verification is skipped entirely and `verify_signature` treats the request as authentic no matter what `X-Hub-Signature` header is sent (or omitted). This is a fail-open default rather than fail-closed.

Once past `verify_signature`, `MembershipHandler#process` unconditionally executes `team.add_member(member)` for `action == 'added'`, creating both the `User` (via `User.find_or_create_by_login!`) and the `Membership` row with no additional check that the named `member.login` is actually a GitHub member of that team/org. [5](#0-4) 

`User#authorized?` grants access purely based on membership rows: `teams.where(id: Shipit.github_teams.map(&:id)).exists?`. [6](#0-5) 

No other guard (`drop_unhandled_event`, `ExplicitParameters` schema in `MembershipHandler.params`) checks GitHub-side team membership; they only validate payload shape.

### Impact Explanation
For any organization configured in Shipit without a `webhook_secret` (or where the operator's org name matches a Shipit-configured org lacking a secret), an unauthenticated attacker can POST a forged `membership` webhook and cause a `Membership` row to be created for an arbitrary GitHub login into a `Team` that is listed in `Shipit.github_teams`. This directly satisfies `User#authorized?`, which gates deploy/API authorization across the app — a High-severity escalation into `Shipit.github_teams` authorization as defined in the rubric. The attack is repeatable for every team ID the attacker knows/guesses and for every organization onboarded without a webhook secret; it is not limited to a single request.

### Likelihood Explanation
Requires: (1) the victim organization is registered in Shipit's GitHub app configuration with a blank/missing `webhook_secret` — a configuration/deployment fact, not something the attacker controls; (2) that organization has `Shipit.github_teams` entries used for authorization. Given these preconditions, attacker cost is minimal — a single unauthenticated `POST /webhooks` with `X-Github-Event: membership` and a crafted JSON body containing existing `team.id`/`organization.login` values (discoverable via public GitHub org/team info) and an arbitrary `member.login`. No GitHub credentials, sessions, or tokens are needed.

### Recommendation
Make `GitHubApp#verify_webhook_signature` fail closed: if `webhook_secret` is blank, reject the webhook (return `false`) rather than treating it as verified, and require configuration validation that every organization referenced by `Shipit.github_teams` has a non-blank `webhook_secret` at boot. Additionally, `MembershipHandler` should independently confirm team membership against the GitHub API (or at minimum log/alert) rather than trusting the webhook payload verbatim for authorization-relevant mutations.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, not to be placed under excluded paths but described conceptually):
```ruby
test "membership webhook forged with blank webhook_secret escalates authorization" do
  # Arrange: configure an org with blank webhook_secret and a team referenced by Shipit.github_teams
  team = shipit_teams(:some_team) # organization: 'victim-org', github_id: 4231
  Shipit.stubs(:github_teams).returns([team])
  github_app = Shipit::GitHubApp.new('victim-org', { webhook_secret: nil })
  Shipit.stubs(:github).with(organization: 'victim-org').returns(github_app)

  payload = {
    action: 'added',
    team: { id: team.github_id, name: team.name, slug: team.slug, url: 'https://api.github.com/teams/4231' },
    organization: { login: 'victim-org' },
    member: { login: 'attacker-login' }
  }.to_json

  # Act: no valid X-Hub-Signature sent (attacker has no secret)
  post shipit.github_webhooks_path, params: payload,
    headers: { 'X-Github-Event' => 'membership', 'Content-Type' => 'application/json' }

  # Assert
  assert_response :ok
  user = Shipit::User.find_by(login: 'attacker-login')
  assert user.present?
  assert_equal false, ' attacker was ever a real GitHub org member' # no GitHub call ever confirmed membership
  assert user.authorized?, "attacker gained Shipit.github_teams authorization via forged webhook"
end
```
This demonstrates both sides of the equality: `verify_signature` accepted the request without any real secret match (`webhook_secret == nil` on `victim-org`), and `User#authorized?` for `attacker-login` transitioned from `false`/nonexistent to `true` purely from the forged payload.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
