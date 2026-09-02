### Title
Webhook signature verification is skippable when `webhook_secret` is unset, allowing forged `membership` events to escalate an attacker into `Shipit.github_teams` authorization - (File: `lib/shipit/github_app.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` is the only gate that binds an inbound webhook payload to a trusted GitHub organization identity before that payload's contents (organization, team, member) are written into Shipit's authorization tables. The gate is implemented by `GitHubApp#verify_webhook_signature`, which unconditionally returns `true` — treating the request as authenticated — whenever no `webhook_secret` is configured for that organization. Because `webhook_secret` is explicitly documented as "optional" and the organization identity itself is a field taken straight from the unauthenticated request body, an attacker who knows (or guesses) the target org's login can submit a forged `membership` webhook that is processed exactly as if GitHub had sent it, granting themselves membership on a `Shipit::Team` that is included in `Shipit.github_teams`.

### Finding Description
The verification chain is: [1](#0-0) 

`repository_owner` — the organization used to select which `GitHubApp`/secret to check against — is itself read out of the untrusted, not-yet-verified JSON body: [2](#0-1) 

The actual cryptographic check is: [3](#0-2) 

`return true unless webhook_secret` means the "verified" binding between "the organization that authenticated this request" and "the organization whose data is written" collapses entirely whenever that org's config omits `webhook_secret` — which the setup docs present as optional: [4](#0-3) [5](#0-4) 

With no secret configured, any POST to `/webhooks` with `X-Github-Event: membership` and a body naming that organization is accepted, and `Shipit::Webhooks::Handlers::MembershipHandler#process` writes it straight into the authorization model: [6](#0-5) 

The `member.login` is resolved/created purely from the payload via `User.find_or_create_by_login!`, then added to the `Team`: [7](#0-6) 

That `Team` membership is exactly what `Authentication#force_github_authentication` and `User#authorized?` rely on to gate access to the whole engine: [8](#0-7) [9](#0-8) 

So the binding that should hold is: `organization that cryptographically authenticated the webhook == organization whose team-membership record is trusted for authorization`. When `webhook_secret` is absent, the left side of that equality is vacuous (`verify_webhook_signature` always returns `true`), while the right side (team/member write) still executes unconditionally.

### Impact Explanation
An attacker who is not a member of any `Shipit.github_teams` team, and holds no Shipit session, ApiClient token, webhook secret, or GitHub App key, can grant themselves membership in a team gating access to Shipit by forging a single unauthenticated HTTP POST. Once `User#authorized?` returns `true`, the attacker passes `force_github_authentication` and gains full authenticated access to the engine — stacks, deploy triggers, rollbacks — i.e., escalation into `Shipit.github_teams` authorization, matching the High-impact criterion in scope.

### Likelihood Explanation
Likelihood is contingent on the target Shipit deployment leaving `webhook_secret` unset for the relevant organization — a state the project's own setup documentation presents as an acceptable, optional configuration rather than a misconfiguration, and the organization login/team id/slug needed in the payload are generally public GitHub information. No other credential or session is required, which is why this crosses the "no credential, repository, execution or authentication boundary crossed" bar the rules require.

### Recommendation
Require `webhook_secret` to be present for any organization configuration that will process events (`membership`, `push`, `status`, `check_suite`), and make `GitHubApp#verify_webhook_signature` fail closed (return `false`) when `webhook_secret` is blank instead of failing open. Additionally, `MembershipHandler` should cross-check that the authenticated `repository_owner`/organization used to pass `verify_signature` matches `params.organization.login` used to create/update the `Team`, so the two can never diverge even under future refactors.

### Proof of Concept
1. Deploy Shipit with a GitHub App configured for organization `acme` but leave `webhook_secret` blank (as permitted by `docs/setup.md`).
2. As an unauthenticated attacker, `POST /webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": {"id": 4242, "name": "Shipit Admins", "slug": "shipit-admins", "url": "https://api.github.com/teams/4242"},
  "organization": {"login": "acme"},
  "member": {"login": "attacker-handle"}
}
```
No `X-Hub-Signature` header (or any arbitrary value) is required, since `verify_webhook_signature` at `lib/shipit/github_app.rb:76-83` returns `true` unconditionally when `webhook_secret` is blank for `acme`.
3. `MembershipHandler#process` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`) creates/fetches `Team` `4242` for `acme`, creates a `User` for `attacker-handle`, and calls `team.add_member(member)`.
4. If team `4242`/`shipit-admins` is listed in `Shipit.github_teams`, the attacker's OAuth login as `attacker-handle` will now satisfy `User#authorized?` (`app/models/shipit/user.rb:80-82`), granting full access to the Shipit instance without ever being a real member of `acme`'s GitHub team.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** config/secrets.development.example.yml (L8-11)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
