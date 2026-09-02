### Title
Webhook signature verification is silently bypassed when no `webhook_secret` is configured, allowing forged `membership` events to grant team-based authorization - (File: `lib/shipit/github_app.rb`)

### Summary
The Balancer report flags a function that is a stub returning a fixed value instead of doing the real computation, so callers get a meaningless answer instead of a verified one. The direct analog in shipit-engine is `GitHubApp#verify_webhook_signature`, which is meant to cryptographically prove that an inbound payload came from GitHub, but silently degrades to "always true" whenever `webhook_secret` is blank — a documented, supported configuration state, not a coding error the operator would notice.

### Finding Description
`WebhooksController#verify_signature` is the only gate in front of `/webhooks`, and it delegates the actual proof-of-authenticity to `GitHubApp#verify_webhook_signature`: [1](#0-0) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

`webhook_secret` is an explicitly optional, documented setting (`webhook_secret: # nil` in every example config, including `config/secrets.development.example.yml` and `docs/setup.md`), so an installation can be running exactly as documented while this check always returns `true`. [3](#0-2) 

The binding that breaks: **"the organization that authenticated" vs "the event data that is trusted and acted on"** collapses to "no authentication at all." Once `verify_signature` passes unconditionally, the controller dispatches to any registered handler based solely on attacker-supplied headers/body: [4](#0-3) 

The most damaging handler reachable this way is `MembershipHandler`, which takes attacker-controlled `team`, `organization`, and `member` fields and directly persists team membership without any additional verification against real GitHub state: [5](#0-4) 

That team membership record is exactly what `User#authorized?` and `force_github_authentication` consult to decide whether a logged-in GitHub identity is allowed to use the whole application: [6](#0-5) [7](#0-6) 

`Shipit.github_teams` resolves the configured OAuth team handles to `Team` records by handle: [8](#0-7) 

Since `MembershipHandler#find_or_create_team!` keys new/matched teams by `github_id` and freely sets `github_team =` / `organization =` from the forged payload, an attacker only needs to submit a `membership` webhook whose `team.id`/`slug` collides with (or gets created to match) an authorized team's `github_id`, and whose `member.login` is the attacker's own already-linked GitHub login, to have themselves added as a member of an authorized team — bypassing the actual GitHub team-membership check entirely.

### Impact Explanation
This crosses the "escalation into `Shipit.github_teams` authorization" High-impact category explicitly listed in scope: an unprivileged external party who is not a member of any authorized GitHub team can grant themselves membership in one via a forged, unsigned webhook, then log in through the normal OAuth flow and pass `authorized?`, gaining full access to the Shipit UI/API (viewing stack state, deploy output, and — depending on further `ApiClient`/OAuth-derived permissions — triggering deploys). It also lets an attacker fabricate arbitrary `push`, `status`, `check_suite`, or `pull_request` events processed by other handlers, since none of them are protected once signature verification is a no-op.

### Likelihood Explanation
This requires the deployment to run with `webhook_secret` unset for the relevant organization — a state the shipped example/development configs and setup docs present as normal and acceptable ("If you've set a webhook secret during the App creation, you should copy it here", implying it is optional). No GitHub App private key, `ApiClient` token, or existing Shipit session is required; the attacker only needs network access to the `/webhooks` endpoint and a GitHub account they can later authenticate with through the app's own OAuth login.

### Recommendation
- Fail closed: if `webhook_secret` is not configured for an organization, reject all webhook deliveries (or refuse to boot/serve that organization's webhook route) instead of treating unsigned requests as verified.
- Make `webhook_secret` mandatory in `GitHubApp#initialize`/config validation rather than `.presence`-optional.
- Add a defense-in-depth check in `MembershipHandler` (and other handlers touching authorization) that cross-validates team/organization identity against the GitHub API rather than trusting webhook body fields unconditionally.

### Proof of Concept
1. Deploy shipit-engine with a valid `github.app_id`/`installation_id`/`private_key` but `webhook_secret` left blank/nil, as shown in the example configs.
2. As an unauthenticated attacker, `POST /webhooks` with header `X-Github-Event: membership` and no (or garbage) `X-Hub-Signature`, body:
```json
{
  "action": "added",
  "team": { "id": <id-of-an-authorized-team>, "name": "Ops", "slug": "ops", "url": "https://api.github.com/teams/1" },
  "organization": { "login": "victim-org" },
  "member": { "login": "attacker-github-login" }
}
```
3. `verify_webhook_signature` returns `true` (no secret configured), the request is dispatched to `MembershipHandler#process`, which upserts the `Team` and adds `attacker-github-login`'s `User` record to it.
4. Attacker completes normal GitHub OAuth login; `User#authorized?` now returns `true` because the forged `Membership` row matches `Shipit.github_teams`, granting full application access.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** config/secrets.development.example.yml (L8-17)
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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```
