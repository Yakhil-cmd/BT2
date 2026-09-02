### Title
Webhook signature verification silently accepts unsigned/forged requests when a GitHub App's `webhook_secret` is unset - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever the target organization's `webhook_secret` config is blank, regardless of what signature (or lack thereof) accompanies the request. Combined with `WebhooksController#verify_signature` deriving the signing organization directly from the untrusted request body (`repository_owner`), any organization configured without a `webhook_secret` accepts arbitrary attacker-crafted webhook payloads, including `membership` events that create `Team`/`Membership` rows and thereby grant `Shipit.github_teams` authorization to attacker-chosen GitHub logins.

### Finding Description
The broken binding: `github_app.verify_webhook_signature(signature, raw_post) == true` should hold **iff** `signature` was produced with `organization.webhook_secret` over `raw_post`. Instead: [1](#0-0) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

returns `true` for *any* input — including a `nil`/missing `X-Hub-Signature` header — as soon as `@webhook_secret = @config[:webhook_secret].presence` is blank for that organization's `GitHubApp` instance.

The controller resolves which organization's app/secret to check purely from the attacker-supplied body: [2](#0-1) [3](#0-2) 

For a `membership` event, `repository_owner` falls back to `params.dig('organization', 'login')`, so the attacker fully controls which org's app config is consulted for `Shipit.github(organization: repository_owner)`.

If that organization (e.g. `shopify`) was configured without a `webhook_secret`, `verify_signature` passes for a completely unsigned request. The request then reaches `MembershipHandler#process`, which trusts the payload: [4](#0-3) 

`find_or_create_team!` looks up (or creates) the `Team` by `params.team.id` (the real victim team id, guessable/enumerable via GitHub's public team APIs or prior legitimate webhook data), and `team.add_member(User.find_or_create_by_login!(params.member.login))` creates a `Membership` for an attacker-chosen login. Any GitHub user later authenticating as that login inherits authorization for that team via `User#authorized?`/`Shipit.github_teams`.

Existing guards do not stop this: `drop_unhandled_event` only checks the event name is registered; the `ExplicitParameters` schema in `MembershipHandler.params` only validates payload shape, not provenance; and `verify_signature`'s only gate — `verify_webhook_signature` — is the exact function that fails open.

### Impact Explanation
An attacker can forge `membership` (or other) webhook events for any organization whose `GitHubApp` is configured with a blank `webhook_secret`, creating `Membership` rows that grant `Shipit.github_teams` authorization to a GitHub login the attacker controls — an authentication bypass that escalates into team-based authorization, matching the Critical/High categories ("authentication bypass (forged webhook ... accepted)" and "escalation into `Shipit.github_teams` authorization"). The attack is repeatable against any organization sharing the same misconfiguration and is not limited to a single repository/stack.

### Likelihood Explanation
This requires the specific, non-default precondition that the target organization's `GitHubApp` config has no `webhook_secret` set — the config field is optional per `docs/setup.md`, and Shipit ships with this fail-open default rather than requiring a secret. If an operator omits `webhook_secret` (e.g., during initial setup, or for an org integration where it was never rotated in), any internet requester can exploit this with zero cost — no signature, token, or session needed. Likelihood is contingent entirely on that configuration state; it is not exploitable against an organization with a properly configured `webhook_secret`.

### Recommendation
Make `verify_webhook_signature` fail closed: reject (return `false`) when `webhook_secret` is blank instead of returning `true`, and/or require `webhook_secret` to be present at `GitHubApp` initialization/config-load time so misconfigured orgs cannot receive webhooks at all. Additionally, consider deriving the organization used for verification from something not fully attacker-controlled (e.g., cross-checking against a known/registered repository or organization) rather than trusting `params.dig('organization','login')` outright.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Stub/configure `Shipit.github(organization: 'shopify')` to be a `GitHubApp` instance built with `webhook_secret: nil` (simulate via `Shipit.github_config` override or constructing `GitHubApp.new('shopify', { webhook_secret: nil, ... })` and stubbing `Shipit.github` to return it) — do **not** stub `verify_signature` itself, exercising the real `verify_webhook_signature` code path.
2. POST to `/webhooks` with `X-Github-Event: membership`, no `X-Hub-Signature` header (or a garbage one), and body:
   ```json
   { "action": "added", "team": { "id": <existing_team.github_id>, "name": "...", "slug": "...", "url": "..." },
     "organization": { "login": "shopify" }, "member": { "login": "attacker-github-login" } }
   ```
3. Assert `assert_response :ok`.
4. Assert `Membership.exists?(team_id: team.id, user: User.find_by(login: 'attacker-github-login'))` is `true`.
5. Assert `User.find_by(login: 'attacker-github-login').authorized?` (or equivalent `Shipit.github_teams` check) is now `true`, demonstrating the equality `verify_webhook_signature(nil/garbage_signature, payload) == true` incorrectly held despite no valid HMAC ever being computed with a real secret — proving the authorization-truth binding was broken.

### Citations

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
