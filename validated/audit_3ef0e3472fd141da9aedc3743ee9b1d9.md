Confirms the equality: `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [1](#0-0) , and `force_github_authentication` grants access to any logged-in user for whom `current_user.authorized?` is true [2](#0-1) . Team membership is written purely from webhook data with no other check.

### Title
Unauthenticated webhook membership spoofing grants Shipit authorization when `webhook_secret` is unset - (File: `lib/shipit/github_app.rb`)

### Summary
`Shipit::GitHubApp#verify_webhook_signature` returns `true` and skips all signature checking whenever an organization's `webhook_secret` is not configured, which is explicitly documented as optional. An attacker who knows (or brute-forces) the numeric `github_id` of a team already present in `Shipit.github_teams` can POST a forged, unsigned `membership` webhook naming themselves as a new member, and `MembershipHandler#process` will persist a `Membership` row with no verification that the request actually came from GitHub.

### Finding Description
The intended binding is: `Membership(team, user) == GitHub-reported team membership` — i.e., a `Membership` row should exist only if GitHub itself reported that event. This binding is broken because `verify_webhook_signature` unconditionally trusts unsigned requests when no secret is configured: [3](#0-2) 

`WebhooksController#verify_signature` calls this method using `Shipit.github(organization: repository_owner)`, where `repository_owner` is taken directly from attacker-controlled JSON (`organization.login` for membership events): [4](#0-3) 

If `verify_webhook_signature` returns `true` (no secret configured for that org), `create` dispatches the raw parsed body straight to `MembershipHandler#process`: [5](#0-4) 

This handler runs `Team.find_or_create_by!(github_id: params.team.id)` (matching an existing `Shipit.github_teams` team by numeric id) and then `team.add_member(User.find_or_create_by_login!(params.member.login))`, creating a `Membership` row for the attacker's chosen login with zero authentication of the webhook's origin.

Downstream, `User#authorized?` treats any user with a `Membership` in a team listed in `Shipit.github_teams` as authorized: [1](#0-0) 

and `force_github_authentication` allows any `authorized?` logged-in user through to all controllers protected by the `Authentication` concern: [2](#0-1) 

No other guard intervenes: `drop_unhandled_event` only checks that a handler is registered for the event name, and the `ExplicitParameters` schema on `MembershipHandler` only validates types/presence, not provenance.

### Impact Explanation
A successful forged request creates a real `Membership` record binding the attacker's GitHub login to a team enumerated in `Shipit.github_teams`, which is Shipit's sole authorization gate for the entire application (deploys, rollbacks, stack management, API tokens, etc. behind the `Authentication` concern). This is a full authentication/authorization bypass: escalation into `Shipit.github_teams` matches the "High" impact category explicitly listed in the rules, and because it grants blanket application access equivalent to a legitimate team member, it borders on the "Critical" authentication-bypass category since it enables unauthorized deploys/rollbacks/merges once "logged in" via OAuth with a matching GitHub account. It is repeatable against any organization configured without a `webhook_secret`, and against any team already tracked in `Shipit.github_teams` for that organization.

### Likelihood Explanation
Exploitation requires: (1) an organization configured in `Shipit`'s GitHub app settings with `webhook_secret` unset — a state the project's own `docs/setup.md` calls "optional," and one of the example config files (`test/dummy/config/secrets_double_github_app.yml`) ships with `webhook_secret: # nil`; (2) knowledge of the numeric `github_id` of a team already present in `Shipit.github_teams` (discoverable via GitHub's public API or UI); (3) the attacker's own GitHub login, which they control. No Shipit secrets, sessions, or API tokens are required — only unauthenticated HTTP access to `POST /webhooks`. This makes the attack low-cost and fully repeatable as long as the precondition (missing `webhook_secret`) holds.

### Recommendation
Require `webhook_secret` to be mandatory for all configured GitHub organizations (fail closed instead of `return true unless webhook_secret`), or at minimum reject/alert on any organization lacking a configured secret rather than silently accepting unsigned webhooks. Update `GitHubApp#verify_webhook_signature` so that a missing `webhook_secret` results in rejection (`false`) rather than automatic trust.

### Proof of Concept
In a minitest under `test/` (e.g., extending `WebhooksControllerTest`), configure a `Shipit::GitHubApp` for an org with `webhook_secret: nil` (mirroring `test/dummy/config/secrets_double_github_app.yml`'s `OrgOne`/`OrgTwo` fixtures), and, without stubbing `verify_signature` (removing the `GithubHook.any_instance.stubs(:verify_signature).returns(true)` blanket stub used in existing tests), send an unsigned membership payload:

```ruby
test "unsigned membership webhook for org without webhook_secret creates a Membership (auth bypass)" do
  team = shipit_teams(:shopify_developers) # already in Shipit.github_teams
  refute Membership.exists?(team:, user: User.find_by(login: 'attacker'))

  request.headers['X-Github-Event'] = 'membership'
  # deliberately no X-Hub-Signature header
  post :create, body: {
    action: 'added',
    team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
    organization: { login: 'orgone' }, # org configured with webhook_secret: nil
    member: { login: 'attacker' }
  }.to_json, as: :json

  assert_response :ok
  assert Membership.exists?(team:, user: User.find_by(login: 'attacker'))
end
```

Assert both sides of the binding diverge: no genuine GitHub-side event occurred (no valid `X-Hub-Signature`), yet `Membership.exists?(team:, user: attacker)` is `true` after the request — proving the write happened without verifying the claimed origin.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
