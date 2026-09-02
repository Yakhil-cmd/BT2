Found a solid analog. The `MembershipHandler` is the most impactful case: `verify_signature` authenticates the request against the `GitHubApp` (and its `webhook_secret`) selected by `repository_owner`, but `MembershipHandler#process` (triggered by the exact same signed payload) reads a completely separate, attacker-controlled field — `params.organization.login` — to decide which `Team`/`Shipit.github_teams` organization membership to grant or revoke, with no check that this equals the organization whose secret actually signed the request.

### Title
Webhook signature verification authenticates a different organization field than the one MembershipHandler trusts to grant team membership - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` used to validate the HMAC signature based on `repository_owner`, computed from `params.dig('repository','owner','login')` with a fallback to `params.dig('organization','login')` [1](#0-0) . Once the signature check passes, `create` re-parses the same raw body and dispatches it to the registered handler for the event [2](#0-1) . For the `membership` event, `Shipit::Webhooks::Handlers::MembershipHandler#process` uses `params.organization.login` — an independent, attacker-controlled JSON field in the very same payload — to look up/create the `Team` and add or remove the specified `member` from it [3](#0-2) . Nothing ties the `organization.login` acted upon by the handler back to the `repository_owner`/organization whose `webhook_secret` actually produced a valid signature.

### Finding Description
In the "Using Multiple GitHub Applications" deployment mode, each GitHub organization has its own GitHub App and its own `webhook_secret` [4](#0-3) . `Shipit.github(organization:)` looks up the app config keyed by that organization name [5](#0-4) , and `verify_webhook_signature` HMAC-verifies the raw body against that specific org's secret [6](#0-5) .

Because `repository_owner` (used to select the verifying secret) and `params.organization.login` (used by `MembershipHandler` to select the `Team`) are two independently-controlled fields inside the same unauthenticated JSON body, an attacker who knows/controls a webhook secret for *any one* onboarded organization (call it `OrgA` — e.g., because they administer that org's GitHub App settings, or the secret otherwise leaked/is weak) can craft a payload where:
- `repository.owner.login` (or `organization.login` if `repository` is absent) = `"OrgA"` → this is what `verify_signature` uses, so the HMAC is computed and checked against `OrgA`'s `webhook_secret`, which the attacker knows.
- The top-level `organization.login` field consumed by `MembershipHandler` = `"OrgB"` (a different, victim organization onboarded to the same Shipit instance).

The signature check passes because it is validated against `OrgA`'s secret using fields chosen by the attacker, but the actual privileged action — creating/matching a `Team` and adding a `member` to it — is performed for `OrgB`, an organization the attacker never proved control of. This breaks the intended binding: *organization that authenticated (`repository_owner` → `OrgA`'s secret) == organization acted upon (`organization.login` → `OrgB`'s team)*.

### Impact Explanation
`Team` membership, populated via this exact webhook path, is the input to `Shipit.github_teams` authorization checks gating access to the entire Shipit application (`force_github_authentication` renders 403 unless the user's teams intersect `Shipit.github_teams`) [7](#0-6) . By forging a `membership` webhook with `action: 'added'`, an attacker who controls only one onboarded organization's webhook secret can add an arbitrary GitHub login (which they also control, since `User.find_or_create_by_login!` will fetch/create that user via the app's own GitHub API token) to a `Team` belonging to a different, victim organization [3](#0-2) . If that `Team` is one of `Shipit.github_teams`, this grants the attacker's GitHub identity authorized access to stacks/deploys gated behind that team — an escalation into `Shipit.github_teams` authorization.

### Likelihood Explanation
This requires the deployment to be running in multi-org mode (`Using Multiple GitHub Applications`, documented and supported) with at least one organization's webhook secret known/controlled by the attacker (e.g., an org they administer being onboarded alongside a more privileged org on the same Shipit instance). This is a plausible deployment pattern explicitly documented in `docs/setup.md`, but not the default single-org configuration.

### Recommendation
- Short term: In `MembershipHandler` (and any other handler that reads an organization/repository identifier from the payload), verify that the identifier used for the privileged action matches the `repository_owner`/organization value that was actually used to select and validate the webhook signature — pass it explicitly from the controller rather than re-deriving it from the untrusted payload.
- Long term: Thread the authenticated organization through `Webhooks.for_event(event).each { |handler| handler.call(params, authenticated_organization:) }` and have every `Handler` subclass assert consistency before acting, plus add tests that assert cross-organization payload forgery is rejected.

### Proof of Concept
1. Deploy Shipit with two organizations configured, `OrgA` and `OrgB`, each with distinct GitHub Apps/`webhook_secret`s (per `docs/setup.md`'s multi-app format) [4](#0-3) , both with teams registered in `Shipit.github_teams`.
2. As an attacker who knows `OrgA`'s `webhook_secret` (e.g. an `OrgA` admin), craft this JSON body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Deployers", "slug": "deployers", "url": "https://example.com" },
  "organization": { "login": "OrgB" },
  "member": { "login": "attacker-controlled-login" },
  "repository": { "owner": { "login": "OrgA" } }
}
```
3. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(OrgA_webhook_secret, body)` and POST it to `/webhooks` with `X-Github-Event: membership`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, calls `Shipit.github(organization: "OrgA").verify_webhook_signature(...)`, which succeeds against the attacker-supplied signature [8](#0-7) .
5. `MembershipHandler#process` executes using `params.organization.login == "OrgB"`, creating/finding `OrgB`'s `Team` and adding `attacker-controlled-login` as a member [9](#0-8) , despite the request never being signed by `OrgB`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
