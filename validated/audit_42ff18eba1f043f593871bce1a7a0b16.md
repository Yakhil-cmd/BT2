This confirms `User#authorized?` at [1](#0-0)  checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` — meaning membership in `Shipit.github_teams` grants login/authorization access to Shipit. This confirms the impact is real and matches the "High" category (escalation into `Shipit.github_teams` authorization).

### Title
Unauthenticated webhook signature bypass allows forged `membership` events to add arbitrary users to `Shipit.github_teams` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
When a `GithubApp` is configured without a `webhook_secret`, `GitHubApp#verify_webhook_signature` unconditionally returns `true`, so `WebhooksController#verify_signature` accepts any unsigned POST to `/webhooks`. An attacker can then forge a `membership` event naming a team ID that matches one of `Shipit.github_teams`, causing `MembershipHandler#process` to add an arbitrary GitHub login as a member of that team, which grants that login access via `User#authorized?`.

### Finding Description
The broken binding is: `verify_webhook_signature(...) == true` is claimed to imply "request is a cryptographically verified GitHub webhook", but this equality only holds when `webhook_secret` is present. When absent, `GitHubApp#verify_webhook_signature` returns `true` unconditionally: `return true unless webhook_secret` ( [2](#0-1) ). `WebhooksController#verify_signature` uses exactly this return value as its sole authentication gate before dispatching to handlers, with `head(422) unless verified` and no other check ( [3](#0-2) ). Once past this gate, `Shipit::Webhooks.for_event('membership')` dispatches to `MembershipHandler`, whose `process` method does `team = find_or_create_team!` (looked up/created by attacker-supplied `team.id`, `team.name`, `team.slug`, `team.url`), resolves/creates a `User` from attacker-supplied `member.login`, and on `action == 'added'` calls `team.add_member(member)` with no further authorization or GitHub-side verification ( [4](#0-3) ). If the attacker supplies a `team.id` matching an existing `Shipit.github_teams` entry, `Team.find_or_create_by!(github_id: params.team.id)` finds that real team and the attacker's chosen `member.login` becomes a member. `User#authorized?` treats team membership as authorization: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` ( [1](#0-0) ). No existing guard (`drop_unhandled_event`, `ExplicitParameters` schema in `MembershipHandler.params`, or model validations) checks the authenticity of the sender — they only validate shape/presence of fields, not their provenance.

### Impact Explanation
An unauthenticated attacker can add any GitHub login of their choosing as a "member" of any team tracked in `Shipit.github_teams`, and that user record then satisfies `User#authorized?`'s team-membership check, which is Shipit's authorization gate for login access when `github_teams` restriction is configured. This is repeatable per request/target team and constitutes an authorization-escalation into `Shipit.github_teams`, matching the High severity category. It does not itself grant a session (OAuth login still requires the attacker to control that GitHub login's OAuth flow), but it removes the team-restriction check for any account the attacker can subsequently authenticate as (including one they own).

### Likelihood Explanation
This requires the specific and non-default misconfiguration where a `GithubApp`'s `webhook_secret` is nil/blank — the setup documentation explicitly instructs operators to set `webhook_secret` ( [5](#0-4) ), and the test dummy config leaves it blank only for test convenience ( [6](#0-5) ). Given that precondition, the attack requires zero credentials: no signature, no session, no API token — just knowledge of a target team's numeric GitHub `id` (discoverable via GitHub's public API) and any login name. The attacker cost is a single unauthenticated HTTP POST, fully repeatable and scriptable against any team ID.

### Recommendation
Require `webhook_secret` to be configured for any `GithubApp` and fail closed (reject or refuse to boot) when it is missing, rather than defaulting `verify_webhook_signature` to `true`. At minimum, `WebhooksController#verify_signature` should treat a missing `webhook_secret` as a hard misconfiguration error (422/500) instead of an implicit pass.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb`-style, but this is a conceptual proof since `test/**` is out of scope for the finding itself):
1. Configure `Shipit.github(organization: 'shopify')` config with `webhook_secret` unset (as in `test/dummy/config/secrets.yml`).
2. `post :create` with `X-Github-Event: membership`, no `X-Hub-Signature` header, and body: `{action: 'added', team: {id: <id of a Shipit.github_teams entry>, name:, slug:, url:}, organization: {login: 'shopify'}, member: {login: 'attacker-chosen-login'}}`.
3. Assert `response :ok` (not 422) — proving `verify_signature` passed with no signature, i.e. `verify_webhook_signature(nil, raw_post) == true` binding held despite no sender verification.
4. Assert a new `Membership` row exists linking the `attacker-chosen-login` user to the targeted `Team` whose `github_id` is in `Shipit.github_teams`.
5. Assert `User.find_by(login: 'attacker-chosen-login').authorized?` returns `true`, demonstrating the authorization-bypass side effect.

### Citations

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```

**File:** test/dummy/config/secrets.yml (L13-13)
```yaml
    webhook_secret: # nil
```
