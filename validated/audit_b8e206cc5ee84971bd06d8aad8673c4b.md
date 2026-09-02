### Title
`Shipit::WebhooksController#repository_owner` picks a decoy `repository.owner.login` for signature verification while `MembershipHandler` mutates team membership for a different, unverified `organization.login` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#repository_owner` resolves the organization used for signature verification via `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, preferring `repository.owner.login` whenever present. `MembershipHandler`, however, only ever reads `params.organization.login` and `params.team`/`params.member`, so an attacker can supply a decoy `repository.owner.login` for an org with no `webhook_secret` (which makes `verify_webhook_signature` return `true` unconditionally) while pointing `organization.login` at a victim org whose real team gets mutated.

### Finding Description
The broken binding: the organization used to authenticate the request, `Shipit.github(organization: repository_owner)` where `repository_owner == params.dig('repository','owner','login')`, must equal the organization whose data is mutated, `params.organization.login` as read by `MembershipHandler#find_or_create_team!`/`#process`. These are NOT the same value for a crafted payload.

Code path:
- `verify_signature` calls `Shipit.github(organization: repository_owner)` and then `github_app.verify_webhook_signature(signature, raw_post)`. [1](#0-0) 
- `repository_owner` prioritizes `repository.owner.login` over `organization.login`. [2](#0-1) 
- `verify_webhook_signature` returns `true` unconditionally when the resolved app's `webhook_secret` is blank: `return true unless webhook_secret`. [3](#0-2) 
- `MembershipHandler` reads only `params.organization.login` (and `team`, `member`); it never inspects `repository`. `find_or_create_team!` sets `team.organization = params.organization.login` and `process` calls `team.add_member(member)` / `team.members.delete(member)` based on that team. [4](#0-3) 

Exploit flow: attacker POSTs to `/webhooks` with `X-Github-Event: membership`, an arbitrary `X-Hub-Signature`, and a body containing both `repository.owner.login = "org-with-no-secret"` and `organization.login = "victim-org"`. `verify_signature` resolves `Shipit.github(organization: "org-with-no-secret")`; since that org has no configured `webhook_secret`, `verify_webhook_signature` returns `true` regardless of the garbage signature. The request passes verification and `#create` dispatches to `MembershipHandler.call(params)`, which uses `params.organization.login == "victim-org"` to find/create a team scoped to `victim-org` and add/remove the specified member from it — all without ever validating a signature against `victim-org`'s real secret.

Existing guards do not stop this: `drop_unhandled_event` only checks that a handler exists for the event type, not which org it targets; `ExplicitParameters` (`MembershipHandler.params`) validates the shape of `organization`/`team`/`member` but performs no cross-check against `repository_owner`; there is no code anywhere that asserts `repository_owner == params.organization.login`.

### Impact Explanation
A completely unauthenticated attacker (no session, no webhook secret, no GitHub App credentials) can create/mutate `Shipit::Team` records and add or remove memberships for an arbitrary victim GitHub organization configured in the Shipit host, as long as at least one other configured organization in the same Shipit instance lacks a `webhook_secret`. Since `Shipit.github_teams` is used for OAuth authorization gating (`Shipit.github_teams`), forged team membership changes can escalate a user's authorization within Shipit. This is repeatable per victim org/team and crosses tenant boundaries within a multi-org Shipit deployment — matching the "escalation into `Shipit.github_teams` authorization" High-severity category, or Critical if it leads to unauthorized deploy/rollback access.

### Likelihood Explanation
Preconditions: the Shipit deployment must have at least two configured GitHub organizations, one of which (attacker-chosen, requires no attacker knowledge, just any org name configured without a `webhook_secret`) and the victim org with `MembershipHandler` wired as the `membership` event handler (default in `Shipit::Webhooks.default_handlers`). [5](#0-4) . The attacker cost is a single unauthenticated HTTP POST with a hand-crafted JSON body; no secrets, sessions, or repository access are required. This is entirely feasible and repeatable against any team/member pair for the victim org, as often as desired.

### Recommendation
Make `repository_owner` (or a dedicated resolution used by `verify_signature`) consistent with the actual organization consumed by the dispatched handler: e.g., derive the verification organization from `params.dig('organization', 'login')` before falling back to `repository.owner.login` for events where `organization` is the canonical source (or better, verify against every org name present in the payload and require they all resolve to the same, secret-bearing organization). Alternatively, after selecting a handler, re-verify that `repository_owner` used for signature checking matches the organization the handler will actually operate on before invoking `handler.call(params)`.

### Proof of Concept
Minitest (`test/controllers/webhooks_controller_test.rb`) plan:
1. Configure test secrets: `org-with-no-secret` present in `secrets.github` config with `webhook_secret` absent; `victim-org` configured with a real webhook secret unknown to the request.
2. Create fixture `Team` for `victim-org` (or allow `find_or_create_team!` to create one).
3. Build payload:
```json
{
  "action": "added",
  "team": {"id": 999, "name": "Victim Team", "slug": "victim-team", "url": "https://example.com"},
  "organization": {"login": "victim-org"},
  "member": {"login": "attacker-controlled-user"},
  "repository": {"owner": {"login": "org-with-no-secret"}}
}
```
4. `@request.headers['X-Github-Event'] = 'membership'`; `@request.headers['X-Hub-Signature'] = 'sha1=deadbeef'` (garbage, never matches victim-org's real secret).
5. `post :create, body: payload.to_json, as: :json`.
6. Assert `assert_response :ok` and assert both sides of the equality:
   - Verified organization side: assert no call ever validated the signature against `victim-org`'s secret (e.g., stub/mock `Shipit.github(organization: 'victim-org').verify_webhook_signature` and assert it is never invoked).
   - Mutated organization side: assert `Team.find_by(organization: 'victim-org', github_id: 999).members.map(&:login)` includes `"attacker-controlled-user"`.
7. This demonstrates the divergence: verification happened against `org-with-no-secret` (unauthenticated), while the write happened against `victim-org` (never authenticated), fulfilling the equality-mismatch requirement.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-43)
```ruby
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
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

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
      end
```
