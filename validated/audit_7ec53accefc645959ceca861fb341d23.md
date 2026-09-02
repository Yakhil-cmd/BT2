### Title
`GitHubApp#verify_webhook_signature` unconditionally accepts unsigned webhooks when a tenant's `webhook_secret` is blank - ([File: lib/shipit/github_app.rb](lib/shipit/github_app.rb))

### Summary
`Shipit::WebhooksController#verify_signature` delegates all trust decisions to `Shipit.github(organization: repository_owner).verify_webhook_signature`, and `organization` is taken verbatim from the attacker-controlled JSON body. `GitHubApp#verify_webhook_signature` returns `true` with no comparison at all when the configured tenant's `webhook_secret` is blank, so any request naming that organization is treated as GitHub-signed regardless of the actual `X-Hub-Signature` header. Combined with `Handlers::MembershipHandler#process`/`#find_or_create_team!`, this lets an unauthenticated caller create/mutate `Team` records and add/remove `Membership` rows for that organization with zero forgery effort.

### Finding Description
Broken binding: `github_app.verify_webhook_signature(sig, body) == true` is asserted by the code to mean "GitHub computed `sig` over `body` using this organization's `webhook_secret`". That equality fails whenever `webhook_secret` is blank, because: [1](#0-0) 

`verify_webhook_signature` short-circuits with `return true unless webhook_secret` before any HMAC comparison is performed, so `sig` need not exist, be valid, or relate to `body` at all.

Path from the request:
1. `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` runs on `POST /webhooks`. [2](#0-1) 
2. `verify_signature` resolves the tenant purely from the attacker-supplied payload via `repository_owner`, then calls the app's `verify_webhook_signature`: [3](#0-2) [4](#0-3) 
   For a `membership` event there is no `repository` key, so `repository_owner` resolves to `params.dig('organization','login')` — the same field the handler later trusts as the team's org.
3. If `verified` is `false`, `head(422)` is called but execution is not `return`ed, so it just sets the response status; however when `webhook_secret` is blank, `verified` is `true` and the request proceeds unimpeded to `create`.
4. `create` dispatches to registered handlers, including `Handlers::MembershipHandler`: [5](#0-4) 
   `find_or_create_team!` uses attacker-supplied `params.team.id` as the lookup/creation key (`github_id`) and writes `params.organization.login` verbatim into `team.organization`; `member` is resolved via `User.find_or_create_by_login!(params.member.login)`, and then added to or removed from the team based on attacker-controlled `params.action`.

No other guard intervenes: `drop_unhandled_event` only checks the event name is registered (`membership` is), `check_if_ping` only special-cases `ping`, and there is no `ExplicitParameters` validation that ties `organization.login`/`team.id`/`member.login` back to a cryptographically verified source — that verification is exactly the responsibility `verify_signature` fails to provide once `webhook_secret` is blank. `Shipit.github(organization:)` does raise `Shipit::GithubOrganizationUnknown` for organizations that aren't configured at all, but that only means the target organization must be one of the configured tenants (a real, documented multi-tenant state), not that it must belong to the attacker.

Attacker request: `POST /webhooks` with header `X-Github-Event: membership`, any/no `X-Hub-Signature`, and body:
```json
{"action":"added","team":{"id":<attacker-chosen>,"name":"x","slug":"x","url":"http://x"},"organization":{"login":"<no-secret-org>"},"member":{"login":"<attacker-login>"}}
```

### Impact Explanation
Any organization configured in Shipit without a `webhook_secret` becomes a universal forgery target for `membership` (and any other) webhooks addressed to it, regardless of who owns that organization on GitHub. The attacker can create or repurpose `Team` rows (`Team#find_or_create_by!(github_id: ...)`) and freely add/remove `Membership` rows via `Team#add_member`/`team.members.delete(member)` without ever possessing that organization's `webhook_secret` — a write to Shipit's authorization data model performed by a request that was never actually authenticated by GitHub. Because `User#authorized?` gates access on membership in `Shipit.github_teams`, if the attacker can align `team.id` with a team already referenced by `Shipit.github_teams`, this becomes a path to `Shipit.github_teams` authorization escalation (High/Critical). At minimum, it is a database write not authenticated by GitHub, repeatable indefinitely against any tenant lacking `webhook_secret`, matching the "authentication bypass (forged webhook ... accepted)" Critical category.

### Likelihood Explanation
Preconditions are exactly as stated in the question: at least one entry in Shipit's multi-tenant GitHub configuration must have `webhook_secret` blank/omitted — a real, supported configuration shape since `GitHubApp#initialize` treats it as optional (`@webhook_secret = @config[:webhook_secret].presence`). No Shipit or GitHub secret, session, or team membership is required by the attacker; a single unauthenticated HTTP POST suffices, and the attack is trivially repeatable.

### Recommendation
`GitHubApp#verify_webhook_signature` should not treat a missing `webhook_secret` as automatic success. Require `webhook_secret` to be present for every configured organization (fail fast at boot/config-load if absent), or make `verify_webhook_signature` return `false` (reject) rather than `true` when `webhook_secret` is blank, and surface a startup/health-check warning for tenants missing this setting.

### Proof of Concept
minitest under `test/controllers/webhooks_controller_test.rb` style (for illustration only; not part of the delivered fix):
1. Configure a `Shipit::GitHubApp` for organization `"no-secret-org"` with `webhook_secret: nil`.
2. `post :create` with headers `X-Github-Event: membership`, `X-Hub-Signature: "sha1=deadbeef"` (or omitted), and body `{"action":"added","team":{"id":9999,"name":"x","slug":"x","url":"http://x"},"organization":{"login":"no-secret-org"},"member":{"login":"walrus"}}`.
3. Assert `response.status == 200` (not `422`), i.e. `github_app.verify_webhook_signature("sha1=deadbeef", raw_body) == true` even though no HMAC was ever computed against `raw_body` with a real secret — the two sides of the binding ("signature verified" vs "GitHub actually signed this body") diverge.
4. Assert `Shipit::Team.find_by(github_id: 9999)` was created with `organization == "no-secret-org"` and that a `Membership` linking `User.find_by(login: "walrus")` to that team now exists, proving an unauthenticated write.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L4-6)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
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
