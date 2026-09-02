### Title
Forged `membership` webhooks bypass GitHub authorization when a `GitHubApp`'s `webhook_secret` is unset - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` unconditionally returns `true` when `@webhook_secret` is blank, so `WebhooksController#verify_signature` accepts unsigned/forged payloads for that organization. Combined with `MembershipHandler#process`, which blindly trusts the `action`/`team`/`member` fields of any accepted `membership` event, an attacker who can send an arbitrary HTTP POST to `/webhooks` can forge a `Membership` row for a team already present in `Shipit.github_teams`, flipping `User#authorized?` to `true` for an account they control.

### Finding Description
The binding the authorization model depends on is:
`Membership(team_id, user_id) exists in Shipit DB` == `GitHub actually reports team_id → user_id membership`.

The only place this equivalence is supposed to be enforced is the webhook signature check, since `MembershipHandler` itself performs no additional verification: [1](#0-0) 

Signature verification is done in `WebhooksController#verify_signature`, which delegates to `Shipit.github(organization: repository_owner).verify_webhook_signature`: [2](#0-1) 

`GitHubApp#verify_webhook_signature` contains an explicit escape hatch: [3](#0-2) 
`return true unless webhook_secret` means that for any organization configured in `Shipit.github` **without** a `webhook_secret` (`@config[:webhook_secret].presence` is `nil`), every webhook — including a completely unsigned one — is treated as verified.

Given that misconfiguration, an attacker who owns/administers a GitHub org matching that config's `organization` key (or who can otherwise cause `repository_owner`/`organization.login` in the payload to resolve to that `GitHubApp` instance) can `POST /webhooks` with header `X-Github-Event: membership` and a body like:
```json
{"action":"added","team":{"id":<existing Shipit::Team github_id>,"name":"x","slug":"x","url":"x"},"organization":{"login":"org"},"member":{"login":"attacker"}}
```
`find_or_create_team!` looks the team up by `github_id` only — it does not re-validate against GitHub — so if that `github_id` matches a `Team` already present in `Shipit.github_teams`, `team.add_member(User.find_or_create_by_login!('attacker'))` creates the `Membership` row directly: [4](#0-3) [5](#0-4) 

Once the attacker logs in through the normal (unprivileged) GitHub OAuth flow to obtain a `session[:user_id]` for the `attacker` login, `User#authorized?` evaluates true because the forged `Membership` satisfies the query: [6](#0-5) 
`Authentication#force_github_authentication` then allows the request through to any `ShipitController` instead of rendering 403: [7](#0-6) 

No other guard intervenes: `drop_unhandled_event` only checks that a handler is registered for the event type, `ExplicitParameters` only validates shape/types (not authenticity), and `MembershipHandler` has no cross-check against GitHub's actual team roster. The only real defense is `verify_webhook_signature`, and it is bypassed by design whenever `webhook_secret` is not configured for that organization.

### Impact Explanation
This is an authentication/authorization bypass: an attacker turns an unauthenticated HTTP POST into a persisted `Membership` for any GitHub team ID already tracked in `Shipit.github_teams`, then self-authorizes into every controller gated by `force_github_authentication` (stacks, deploys, tasks, rollbacks, API client management, etc.) for the entire Shipit instance. The attack is repeatable for any `github_id` present in `Shipit.github_teams` and is not scoped to a single repository — it grants access to the whole application for the organization whose `GitHubApp` lacks a `webhook_secret`.

### Likelihood Explanation
This requires a specific, non-default operator misconfiguration: a `GitHubApp` entry (keyed by organization) in `Shipit.github` that has no `webhook_secret` set while `Shipit.github_teams` authorization is enabled and already contains at least one team from that organization. `docs/setup.md` documents `webhook_secret` as part of the expected GitHub App configuration, so this is a deployment error rather than the documented default, but the engine's own code does not prevent or warn about the combination, and nothing else re-validates membership events against GitHub. Given the misconfiguration exists, the attack requires only a single crafted HTTP POST and a normal OAuth login — no secrets, no privileged role.

### Recommendation
- Make `webhook_secret` mandatory for any organization used with `Shipit.github_teams`, or fail closed (reject the webhook) instead of returning `true` when `webhook_secret` is blank, e.g. change `GitHubApp#verify_webhook_signature` to `return false unless webhook_secret` and add explicit boot-time validation that all orgs referenced by `Shipit.github_teams` have a configured secret.
- Alternatively/additionally, have `MembershipHandler` reconcile forged/added memberships against a live GitHub API call (`org_team_membership`) before writing the `Membership` row, rather than trusting webhook payload content unconditionally.

### Proof of Concept
Minitest plan (no live GitHub calls):
1. Configure a test `GitHubApp` for organization `"forgeable-org"` with `webhook_secret: nil` in `Shipit.github` test config; create a `Shipit::Team` with `organization: "forgeable-org"`, `github_id: 42`, and add its `github_id` to `Shipit.github_teams`.
2. Assert precondition: `Shipit::Membership.where(team_id: team.id, user_id: attacker_placeholder).exists?` is `false`, and `Shipit::Team.find_by(github_id: 42).members.map(&:login)` does not include `"attacker"`.
3. `POST shipit.webhooks_path`, headers `{'X-Github-Event' => 'membership', 'X-Hub-Signature' => 'sha1=bogus'}`, body `{"action":"added","team":{"id":42,"name":"x","slug":"x","url":"x"},"organization":{"login":"forgeable-org"},"member":{"login":"attacker"}}` — no stubbing of `verify_webhook_signature` needed, since `webhook_secret` is nil it returns `true` unconditionally; assert response is `200`.
4. Assert `Shipit::Team.find_by(github_id: 42).members.map(&:login)` now includes `"attacker"`, i.e. the binding is broken: a `Membership` row now exists that GitHub never actually reported.
5. `user = Shipit::User.find_by(login: 'attacker')`; set `session[:user_id] = user.id` in a controller test for a `ShipitController`-derived action (e.g. `StacksController#index`) with `Shipit.authentication_disabled?` false; assert `user.authorized?` is `true` and the response is `200` rather than `403`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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
