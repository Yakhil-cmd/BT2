### Title
Webhook Signature Verification Silently No-ops When `webhook_secret` Is Unset, Letting an Unauthenticated Attacker Forge GitHub Events and Escalate `Shipit.github_teams` Membership - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` contains an early-return bypass structurally identical to Root Cause A of the referenced report: instead of failing closed when the verification material is unavailable, it silently returns "verified" and lets an unvalidated payload flow into privileged business logic.

### Finding Description
`WebhooksController#verify_signature` is the sole authentication gate for `POST /webhooks`. It derives the GitHub App/org context from the untrusted request body and delegates the actual HMAC check to `GitHubApp#verify_webhook_signature`: [1](#0-0) 

That method is: [2](#0-1) 

The first line, `return true unless webhook_secret`, is the exact analog of the report's Root Cause A "early-return bypass": when the verification material (`webhook_secret`) is unavailable, the function returns an unconditional "pass" instead of reverting/failing closed, exactly like `checkPoolAndGetCenterPrice()` returning the raw spot price instead of reverting when the TWAP couldn't be computed.

`webhook_secret` is explicitly documented as optional/nil-by-default: [3](#0-2) 

Once verification is bypassed, `WebhooksController#create` dispatches the fully attacker-controlled JSON body directly to handlers: [4](#0-3) 

The `membership` handler acts directly on `Shipit::Team`/`Membership` records based on payload content with no further authentication check, e.g. adding an attacker-chosen GitHub login to a `Shipit.github_teams`-recognized team, or creating a new team from an arbitrary payload: [5](#0-4) 

The broken binding is: **"HMAC-signature-verified == request genuinely originated from GitHub for this organization."** When `webhook_secret` is absent for an organization, `verify_webhook_signature` makes this equality vacuously true for every request, regardless of the `X-Hub-Signature` header's actual value.

### Impact Explanation
An unauthenticated, unprivileged network attacker who knows (or guesses) a configured `repository_owner`/organization login handled by this Shipit instance can POST arbitrary JSON to `/webhooks` and have it processed as a genuine GitHub event whenever that organization has no `webhook_secret` configured (the documented default). This allows:
- Adding/removing arbitrary GitHub logins to/from `Team`/`Membership` records, directly escalating into `Shipit.github_teams` authorization (a listed High-impact category), since `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) .
- Forging `push`/`status`/`check_suite` events to trigger `GithubSyncJob`, fake commit statuses, or check-run refreshes, corrupting the state a stack's deploy/merge decisions are based on.

### Likelihood Explanation
Likelihood is high wherever an operator leaves `webhook_secret` unset for an organization — the shipped example configuration explicitly ships this field as blank/nil, so it is a realistic and even encouraged starting configuration, not an edge case requiring credential theft.

### Recommendation
Fail closed instead of returning `true` when no `webhook_secret` is configured: reject (`422`) or require a mandatory secret at boot/config-validation time. Never let an early-return in a security-gate method return an "authenticated" result derived from the absence of verification material — mirror the "revert when TWAP unavailable" fix from the report rather than the "return raw price" behavior.

### Proof of Concept
1. Configure Shipit for organization `acme` without `webhook_secret` (per the shipped example config).
2. As an anonymous attacker, `POST /webhooks` with header `X-Github-Event: membership` and a crafted body:
```json
{"action":"added","team":{"id":<victim_team_id>,"name":"...","slug":"...","url":"..."},"organization":{"login":"acme"},"member":{"login":"attacker-controlled-login"},"repository":{"owner":{"login":"acme"}}}
```
3. `verify_webhook_signature` returns `true` unconditionally (no `webhook_secret`), the request passes `verify_signature`, and `MembershipHandler` processes it, granting the attacker's GitHub login membership in a `Shipit.github_teams`-authorized team as shown by the analogous test flow at [7](#0-6) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** test/controllers/webhooks_controller_test.rb (L129-165)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end

    test ":membership creates the mentioned user on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      Shipit.github.api.expects(:user).with('george').returns(george)
      assert_difference -> { User.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'george' }).to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can delete an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, -1 do
        post :create, body: membership_params.merge(action: 'removed').to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can append an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'bob' }).to_json, as: :json
        assert_response :ok
      end
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
