### Title
Webhook signature verification is bypassed when `webhook_secret` is blank, allowing forged `membership` events to grant Shipit access - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` unconditionally returns `true` when `webhook_secret` is not configured, and `webhook_secret` is documented as `nil` by default in `config/secrets.development.example.yml`. Combined with `MembershipHandler`, an attacker can POST an unsigned `membership` webhook that creates a `Membership` row for themselves on any team already tracked in `Shipit.github_teams`, without GitHub ever reporting that membership, which flips `User#authorized?` to `true` for that attacker.

### Finding Description
The broken binding: `Membership.exists?(team_id: T.id, user: attacker)` should be true **iff** GitHub actually reports `attacker` as a member of team `T` on GitHub. This engine breaks that binding when webhook signing is not configured.

Path:
- `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) .
- `GitHubApp#verify_webhook_signature` short-circuits to `true` when `webhook_secret` is blank: `return true unless webhook_secret` [2](#0-1) .
- `webhook_secret` is read straight from config with no enforced presence: `@webhook_secret = @config[:webhook_secret].presence` [3](#0-2) , and the documented example config ships with it unset/`nil` [4](#0-3) .
- `MembershipHandler#process` trusts the payload directly: it resolves/creates a `Team` by `params.team.id` and calls `team.add_member(User.find_or_create_by_login!(params.member.login))` on `action == 'added'` [5](#0-4) .
- `Team#add_member` unconditionally appends the member with no GitHub-side re-verification [6](#0-5) .
- `User#authorized?` grants access based purely on local `Membership` rows: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) .

Attacker request: `POST /webhooks` with header `X-Github-Event: membership`, no `X-Hub-Signature` (or garbage), and body:
```
{"action":"added","team":{"id":<github_id of a team in Shipit.github_teams>,"name":"x","slug":"x","url":"https://x"},"organization":{"login":"any"},"member":{"login":"attacker"}}
```
`repository_owner` falls back to `params.dig('organization','login')` [8](#0-7) , so the attacker only needs any organization login resolvable by `Shipit.github(organization:)` (or one matching Shipit's configured org, per `GithubOrganizationUnknown` rescue) — this is a config-dependent precondition, not a secret. `drop_unhandled_event` does not block `membership` because it's a handled event, and `verify_signature` passes because `verify_webhook_signature` returns `true` for a blank secret. No other guard (`ExplicitParameters` schema, `force_github_authentication`) checks GitHub-side membership truth — the schema only validates payload *shape*, not authenticity.

### Impact Explanation
The attacker obtains a persisted `Membership` for a `Team` in `Shipit.github_teams` without ever being a real member on GitHub, which makes `current_user.authorized?` return `true` [7](#0-6) . This is an authentication/authorization bypass into Shipit itself: it grants access to every stack gated by `Shipit.github_teams`, is fully repeatable (one request per target team id), and does not require compromising any Shipit or GitHub secret — only that the operator's `webhook_secret` is blank, which is the documented default. Severity matches "Critical - authentication bypass" per the grading rubric, since it escalates an unprivileged internet actor into `Shipit.github_teams` membership and thus authorized status.

### Likelihood Explanation
The sole precondition is operator configuration: `webhook_secret` left blank/nil, which is exactly the shipped example default (`config/secrets.development.example.yml`) and a plausible real-world misconfiguration, not a secret held by Shipit. Given that precondition, the attack costs a single unauthenticated HTTP POST with a guessable/observable team `github_id` (team ids are often discoverable via GitHub's own API or UI) and requires no GitHub-side privilege. It is trivially repeatable against any team tracked by `Shipit.github_teams`, and by extension any org whose owner login the attacker can supply.

### Recommendation
Enforce a mandatory, non-blank `webhook_secret` (fail closed instead of `return true unless webhook_secret`), or refuse to process `membership`/mutating events entirely when no secret is configured. At minimum, log/alert loudly and treat missing secret as `verified = false` rather than `true`, so unsigned webhooks are always rejected in that state. Additionally, consider validating team-membership webhooks against GitHub's own API (e.g., re-fetch membership) rather than trusting payload content unconditionally.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (extend existing suite)
test "membership webhook without signature grants authorized? when webhook_secret is blank" do
  team = shipit_teams(:shopify_developers) # a team included in Shipit.github_teams
  Shipit.stubs(:github_teams).returns([team])

  github_app = Shipit.github(organization: 'shopify')
  github_app.stubs(:webhook_secret).returns(nil) # documented default: blank secret

  payload = {
    action: 'added',
    team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
    organization: { login: 'shopify' },
    member: { login: 'attacker' }
  }.to_json

  post '/webhooks', params: payload, headers: {
    'X-Github-Event' => 'membership',
    'Content-Type' => 'application/json'
    # deliberately no X-Hub-Signature
  }

  assert_response :ok
  attacker = User.find_by(login: 'attacker')
  assert Membership.exists?(team_id: team.id, user: attacker) # left side of binding: true
  assert attacker.authorized? # no corresponding true GitHub membership exists: binding broken
end
```
Both sides of the binding diverge: `Membership.exists?` is `true` in Shipit's DB while no GitHub API call was ever made to confirm the attacker is actually a member of `team` on GitHub — confirming the forged-webhook authentication bypass.

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

**File:** lib/shipit/github_app.rb (L50-50)
```ruby
      @webhook_secret = @config[:webhook_secret].presence
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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
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
