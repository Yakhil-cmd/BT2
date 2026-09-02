### Title
Empty-string `webhook_secret` silently disables webhook signature verification, enabling forged `membership` webhooks that escalate into `Shipit.github_teams` authorization - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` short-circuits with `return true unless webhook_secret`, and the instance variable is assigned via `@config[:webhook_secret].presence`. Because `''.presence` is `nil`, an operator-configured empty-string `webhook_secret` is silently treated as "no secret configured," making the method return `true` unconditionally without ever computing or comparing an HMAC. This is worse than the brute-forceable-HMAC scenario posed in the question: no computation is needed at all, any (or no) `X-Hub-Signature` value passes.

### Finding Description
The claimed binding is: `signature presented == OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message)`. Tracing the code: [1](#0-0) [2](#0-1) 

`@webhook_secret = @config[:webhook_secret].presence` turns an empty string into `nil`. `verify_webhook_signature` then executes `return true unless webhook_secret` before any HMAC is computed — for an org configured with `webhook_secret: ''`, the method always returns `true`, regardless of the signature header or payload content. The equality the question describes is never evaluated; it is bypassed entirely.

The controller trusts this return value directly: [3](#0-2) 

`repository_owner` (and thus which `GitHubApp`/secret is selected) is taken straight from the untrusted JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), so the attacker fully controls which org's `GitHubApp` instance is used for verification. [4](#0-3) 

Exploit flow for the org whose config has `webhook_secret: ''`:
1. Attacker POSTs to `/webhooks` with `X-Github-Event: membership`, any/garbage `X-Hub-Signature`, and a payload naming that org as `organization.login` / `repository.owner.login`.
2. `verify_signature` resolves `Shipit.github(organization: <that org>)` and calls `verify_webhook_signature`, which returns `true` immediately (no comparison performed).
3. `Shipit::Webhooks.for_event('membership')` dispatches to `MembershipHandler#process`. [5](#0-4) 

4. `find_or_create_team!` creates/finds a `Team` keyed by attacker-supplied `params.team.id`, and `case 'added'` calls `team.add_member(member)`, adding an attacker-controlled `User` (created by login) to that `Team`. [6](#0-5) 

If that `github_id`/`Team` matches an entry in `Shipit.github_teams`, the added member now satisfies `User#authorized?`: [7](#0-6) 

None of the existing guards prevent this: `check_if_ping`/`drop_unhandled_event` only gate on event type, `ExplicitParameters` only validates payload shape (not authenticity), and `verify_signature` is the sole authenticity gate — which is defeated by the `.presence` coercion.

### Impact Explanation
For the misconfigured org, an attacker can forge arbitrary `membership` webhooks with zero cryptographic effort (not even a correct HMAC is required), causing Shipit to write `Team`/`Membership` records that were never actually authenticated by GitHub. If the targeted team ID overlaps an entry in `Shipit.github_teams`, this becomes an escalation into Shipit's authorization system, granting `User#authorized?` to an attacker-controlled account — matching "escalation into `Shipit.github_teams` authorization" (High), and arguably "authentication bypass (forged webhook accepted)" (Critical) since the whole webhook signature scheme is inert for that org. The blast radius is scoped to whichever org(s) share this misconfiguration but is fully repeatable per request, and other webhook types (`push`, `status`, `check_suite`) for the same org are equally forgeable.

### Likelihood Explanation
Requires an operator to have configured `webhook_secret: ''` (empty string) rather than omitting the key or using a non-empty value — a plausible misconfiguration (e.g., a templated secrets file with a blank placeholder left unfilled) but not something the attacker can cause themselves. Given that precondition, exploitation cost is trivial: a single unauthenticated HTTP POST with any signature value. No knowledge of a real secret, GitHub session, or Shipit credentials is needed.

### Recommendation
In `lib/shipit/github_app.rb`, do not conflate "no secret configured" with "empty-string secret." Either treat a present-but-blank `webhook_secret` as a hard configuration error (raise on boot) rather than silently disabling verification, or drop the `.presence` coercion so an explicit empty string is compared literally (and fails HMAC comparison) instead of matching the `unless webhook_secret` bypass branch.

### Proof of Concept
Add to `test/unit/github_apps_test.rb` (or a new file):
```ruby
test "#verify_webhook_signature returns false, not true, for an empty-string webhook_secret" do
  app = GitHubApp.new('shopify', double_github_app_config.deep_merge(webhook_secret: ''))
  # Binding under test: signature presented == HMAC computed with configured secret.
  # Left side: attacker-supplied bogus signature.
  bogus_signature = 'sha1=deadbeef'
  message = '{"anything":"goes"}'
  refute app.verify_webhook_signature(bogus_signature, message),
    "empty-string webhook_secret must not be treated as 'no verification required'"
end
```
And at the controller level:
```ruby
test "membership webhook is rejected when org webhook_secret is empty string" do
  Shipit.stubs(:github).with(organization: 'shopify')
    .returns(GitHubApp.new('shopify', double_github_app_config.deep_merge(webhook_secret: '')))

  @request.headers['X-Github-Event'] = 'membership'
  assert_no_difference -> { Team.count } do
    post :create, body: membership_params.to_json, as: :json
    assert_response :unprocessable_entity  # currently fails: returns :ok and creates the Team/Membership
  end
end
```
Both assertions currently fail against the present code (`verify_webhook_signature` returns `true`, `MembershipHandler#process` runs and mutates `Team`/`Membership`), demonstrating the broken binding.

### Citations

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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
