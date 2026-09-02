### Title
Unsigned webhook accepted and Team membership mutated for any organization with unset `webhook_secret` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` derives the organization used for signature verification from attacker-controlled payload fields (`repository.owner.login`, falling back to `organization.login`), and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that organization has no `webhook_secret` configured. An attacker who names any organization lacking a configured secret (e.g. `OrgTwo`) causes the request to be treated as verified with zero signature, after which `MembershipHandler#process` writes a `Team`/`Membership` row scoped to that same organization.

### Finding Description
The binding under test is: *organization whose secret authenticated the request bytes* == *organization whose `Team`/`Membership` row is mutated*. Trace:

- `repository_owner` reads `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  — fully attacker-controlled in a `membership` event payload that omits `repository`.
- `verify_signature` looks up `Shipit.github(organization: repository_owner)` and calls `verify_webhook_signature` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` has `return true unless webhook_secret` [3](#0-2) . If the named organization has no `webhook_secret` configured, any request — signed or not — passes verification.
- `MembershipHandler#process` then runs `find_or_create_team!` (which sets `team.organization = params.organization.login`) and `team.add_member(member)` [4](#0-3) , using the same `organization.login` value the attacker supplied.

Because both the verification organization and the mutation organization are read from the same attacker-supplied `organization.login` field, they trivially "match" — but the match is meaningless: verification for that organization is a no-op (`return true unless webhook_secret`) rather than a cryptographic check. The real broken invariant is not cross-tenant confusion (organization A's secret authorizing organization B's mutation) but the absence of any authentication requirement at all for organizations that have not set a `webhook_secret`. `drop_unhandled_event` and `check_if_ping` don't block `membership` events, and there is no `ExplicitParameters` or model check that requires a valid signature independent of whether a secret happens to be configured.

The exploit: attacker POSTs to `/webhooks` with header `X-Github-Event: membership`, no `X-Hub-Signature`, and body `{"action":"added","team":{...},"organization":{"login":"OrgTwo"},"member":{"login":"attacker"}}`. If `OrgTwo` has never had a `webhook_secret` set in `Shipit.github_teams`/config, the request passes `verify_signature` unauthenticated, and a `Membership` row is created binding the attacker's `User` to a `Team` under `OrgTwo`.

### Impact Explanation
This is an authentication bypass: an unsigned, unprivileged HTTP request is treated as a legitimate GitHub webhook and used to mutate persistent state (`Team`/`Membership` rows) for a real organization, `OrgTwo`. Repeated against any organization configured in this Shipit instance without a `webhook_secret`, an attacker can add themselves (or any GitHub login) as a member of that organization's `Team` record inside Shipit. Since `oauth_teams`/team membership can gate authorization elsewhere in the app (e.g. `Shipit.github_teams` checks), this is a path toward `Shipit.github_teams` escalation if `OrgTwo`'s team is used for authorization decisions. This matches the "authentication bypass (forged webhook accepted)" Critical/High category, scoped to any tenant organization lacking a `webhook_secret`.

### Likelihood Explanation
Preconditions: the operator must run at least one configured GitHub organization/app entry (`OrgTwo`) with `webhook_secret` unset or blank — a realistic misconfiguration since `@webhook_secret = @config[:webhook_secret].presence` silently accepts `nil`/blank with no validation or startup check [5](#0-4) . No attacker secrets are needed; the attacker only needs to know or guess an organization name configured on the Shipit instance and craft a JSON POST — trivially repeatable and cheap.

### Recommendation
Do not treat "no configured secret" as automatically verified. `GitHubApp#verify_webhook_signature` should fail closed (return `false`/reject) when `webhook_secret` is blank in production, or the application should refuse to boot/register a GitHub organization without a configured `webhook_secret`. Additionally, `WebhooksController` should not trust attacker-supplied `organization.login`/`repository.owner.login` for selecting which secret to verify against without first validating the signature against a fixed, operator-configured lookup, or should require signature verification succeed against every configured secret rather than short-circuiting on absence.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb` style (not modifying `test/**`, but describing the plan):
1. Configure `Shipit.github(organization: 'OrgTwo')` (or the relevant fixture) with `webhook_secret` set to `nil`/blank, and a distinct `OrgOne` with a real secret.
2. POST to `/webhooks` with header `X-Github-Event: membership`, **no** `X-Hub-Signature` header, and body:
   `{"action":"added","team":{"id":1,"name":"T","slug":"t","url":"http://x"},"organization":{"login":"OrgTwo"},"member":{"login":"attacker"}}`.
3. Assert response is `200 OK` (not `422`), and assert `Membership.count` increased by 1, with `Team.find_by(organization: 'OrgTwo').members.map(&:login)` including `"attacker"`.
4. Contrast: repeat with `organization.login: 'OrgOne'` and no signature, and assert response is `422` and `Membership.count` unchanged, confirming the divergence is solely due to `OrgTwo`'s missing `webhook_secret`.

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

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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
