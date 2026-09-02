Confirmed: `membership` events are routed to `Handlers::MembershipHandler` [1](#0-0) , and the controller's signature verification key (`repository_owner`) is computed independently from the fields the handler actually acts on, creating the exploitable mismatch described below.

### Title
Cross-organization webhook signature confusion allows privilege escalation into `Shipit.github_teams` authorization - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to verify a request against using a field taken directly from the untrusted, not-yet-verified JSON body (`repository.owner.login` or `organization.login`), while the downstream event handler acts on a *different* field of that same body (e.g. `team.id`, `member.login`, or `repository.full_name`) without ever confirming it belongs to the organization whose secret was used for verification. In a multi-organization Shipit deployment, an attacker who legitimately controls one configured GitHub App/organization (and therefore knows its real webhook secret) can sign a payload with that secret while setting the "acted upon" fields to target a completely different organization's data — most critically, adding themselves to an arbitrary `Team` used for `Shipit.github_teams` authorization.

### Finding Description
`verify_signature` derives the signing key purely from attacker-controlled JSON:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`Shipit.github(organization:)` looks up the per-organization app config/secret from `secrets.github`, and Shipit explicitly supports multiple organizations configured under one instance (`github_organizations`, `github_app_config`) [3](#0-2) .

The HMAC only proves the request was signed with *some* configured organization's secret (the one named in `organization.login`/`repository.owner.login`); it does not bind any other field in the payload. Yet `MembershipHandler#process` trusts the `team` and `member` sub-objects of the very same payload to mutate authorization state, independent of which organization's secret matched:

```ruby
def process
  team = find_or_create_team!
  member = User.find_or_create_by_login!(params.member.login)
  case params.action
  when 'added'
    team.add_member(member)
  ...
end

def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [4](#0-3) 

`Team` records looked up here are the same objects consumed by `Shipit.github_teams` (built from `github.oauth_teams`) [5](#0-4) , and `User#authorized?` grants full application access to any user who is a member of one of `Shipit.github_teams` [6](#0-5) , gated by `force_github_authentication` in `Authentication` [7](#0-6) .

Because the `organization.login` used for signature selection and the `team.id`/`member.login` used for the actual authorization write are independent, uncorrelated fields inside the same forgeable JSON body, an attacker who legitimately controls Org A's GitHub App (and thus knows Org A's webhook secret) can:
1. Set `organization.login = "org-a"` so `verify_signature` fetches and validates against Org A's real secret.
2. Set `team.id` to the `github_id` of a `Team` referenced in `Shipit.github_teams` for a different, victim organization/deployment tenant, and `member.login` to their own GitHub login.
3. Sign the crafted body with Org A's secret and POST it to `/webhooks`.

The signature check passes (Org A's secret matches), and `MembershipHandler` then adds the attacker as a member of the victim's authorization team, exactly mirroring the analog rule "an organization that authenticated versus the repository [team] that is written."

### Impact Explanation
This breaks the deployment-trust binding between "the organization whose credential authenticated the request" and "the team/authorization record the request modifies." Successful exploitation grants the attacker membership in a `Shipit.github_teams` team, which is the exact gate checked by `force_github_authentication`/`User#authorized?` for the whole Shipit instance [6](#0-5) . That is a direct escalation into `Shipit.github_teams` authorization, letting an outsider (control of one unrelated org's GitHub App) obtain full deploy/rollback/merge privileges across the Shipit instance — matching the "High" impact bucket ("escalation into `Shipit.github_teams` authorization").

### Likelihood Explanation
Requires the deployment to configure more than one GitHub organization (a documented, supported configuration via `TOP_LEVEL_GH_KEYS`/`github_app_config`) and requires the attacker to know/guess the numeric `github_id` of the victim team (obtainable via GitHub's team API if the team is visible to the attacker, or via prior webhook traffic). Given these preconditions, no session, no `ApiClient` token, and no access to the victim organization's own webhook secret are needed — only control of one's own, unrelated, configured GitHub App.

### Recommendation
Bind webhook processing to the same identity that was cryptographically verified: after `verify_signature` succeeds, re-derive/pass down the verified organization and reject (or use it to override) any `organization.login`/`repository.owner.login`/`team.organization` value in the body that doesn't match. `MembershipHandler#find_or_create_team!` should require `params.organization.login == <verified organization>` before creating/mutating a `Team`, and more generally every handler should validate that the object it mutates belongs to the organization whose secret produced a valid signature.

### Proof of Concept
1. Configure Shipit with two GitHub Apps, `org-a` and `org-b`, where `org-b` has a Team `github_id: 999` referenced in `Shipit.github_teams`.
2. As an attacker who administers `org-a`'s GitHub App (knows `org-a`'s `webhook_secret`), craft:
```json
{
  "action": "added",
  "organization": {"login": "org-a"},
  "team": {"id": 999, "name": "Deployers", "slug": "deployers", "url": "https://api.github.com/teams/999"},
  "member": {"login": "attacker-github-login"}
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(org-a-secret, body)>` and POST it to `/webhooks` with `X-Github-Event: membership`.
4. `verify_signature` resolves `Shipit.github(organization: "org-a")`, validates successfully.
5. `MembershipHandler` finds/creates the `Team` with `github_id: 999` (the victim's authorization team) and adds `attacker-github-login` as a member.
6. Attacker logs into Shipit via OAuth; `User#authorized?` now returns `true` because the attacker is a member of a team in `Shipit.github_teams`, granting full deploy/rollback access across the instance.

### Citations

**File:** app/models/shipit/webhooks.rb (L6-22)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
    end
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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
