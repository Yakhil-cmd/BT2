### Title
Webhook signature-verification organization is decoupled from the organization/repository the payload handler actually acts on, allowing forged webhook events to be authenticated against an attacker-controllable org - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate `X-Hub-Signature` against using `repository_owner`, a value pulled straight from the attacker-supplied JSON body (`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`). The handlers that actually act on the payload (`Handler#repository_name`, `MembershipHandler#find_or_create_team!`) read *different* payload fields (`repository.full_name`, `organization.login`) to decide which `Stack`/`Team`/organization to mutate. Because both fields live in the same attacker-controlled JSON body and are never cross-validated, an attacker can pick a lightly-secured (or unconfigured) organization to satisfy signature verification while directing the actual side effect at a different, protected organization/repository tracked by the same Shipit instance.

### Finding Description
`verify_signature` in [1](#0-0)  computes:

```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```

where `repository_owner` is: [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization config block (`app_id`, `private_key`, `webhook_secret`) as documented for multi-org installs: [3](#0-2) . Multiple shipped secrets templates explicitly allow `webhook_secret` to be `nil` per organization: [4](#0-3) .

`GithubApp#verify_webhook_signature` trivially returns `true` when no secret is configured for the selected organization: [5](#0-4) .

After verification, `WebhooksController#create` dispatches the *raw parsed body* to handlers unchanged: [6](#0-5) .

Handlers determine the target `Stack`/`Repository` from a *different* field of the same body: [7](#0-6) 

or, for organization-level events, from `organization.login` directly: [8](#0-7) 

Because `repository_owner` in the controller prefers `repository.owner.login` over `organization.login`, an attacker can attach an arbitrary, unvalidated `repository` object to any event payload (handler parameter schemas, e.g. `MembershipHandler.params`, do not reject extra top-level keys) purely to steer which org's secret is checked, while the real `organization.login`/`repository.full_name` used by the handler point at a completely different, protected organization/repository hosted on the same Shipit instance.

This breaks the intended binding: **organization authenticated (signature check) == organization/repository written (handler side effect)**. Before a fix, these two must be the same GitHub org; after this bug, an attacker fully controls both independently in a single POST body.

### Impact Explanation
The `membership` webhook handler creates/updates `Team` records and adds arbitrary GitHub logins as team members purely from payload data, with no re-verification against GitHub: [9](#0-8) . `Shipit.github_teams` (the set of teams used for authorization) is resolved by organization/slug lookup: [10](#0-9)  and [11](#0-10) , and `User#authorized?` simply checks team membership: [12](#0-11) .

If an attacker forges a `membership` event whose `repository.owner.login` points to an org with no/weak `webhook_secret`, but whose `organization`/`team` fields target a real, protected organization/team referenced in `Shipit.github_teams`, they can add themselves as a member of an authorization-controlling Team, escalating into `Shipit.github_teams` authorization — matching the High-severity criteria in scope. Push-type events could similarly cause `stack.sync_github` to run against a Stack belonging to an organization whose signature was never actually checked.

### Likelihood Explanation
This requires: (1) the Shipit instance to be configured with more than one GitHub App/organization (a documented, supported configuration — see `config/secrets.development.shopify.yml`, `secrets_double_github_app.yml`, `config/secrets.development.example.yml`), and (2) at least one configured organization with `webhook_secret` unset/weak (also explicitly shown as a supported, "optional" configuration in `docs/setup.md`). No credentials, tokens, or privileged access to Shipit are required — the `/webhooks` endpoint is unauthenticated by design and only gated by this flawed check. The forged request is a single unauthenticated HTTP POST.

### Recommendation
Cross-validate the organization used to select the signing secret against the organization actually referenced by the handler-relevant fields (`repository.full_name`'s owner and/or `organization.login`) before dispatching to handlers, and reject the request if they diverge. Alternatively, always compute `repository_owner` from a single canonical, handler-consistent field, and require a non-blank `webhook_secret` for every configured organization (fail closed rather than open when `webhook_secret` is absent).

### Proof of Concept
Given a multi-org Shipit deployment with `OrgA` (no `webhook_secret` configured) and `OrgB` (a real org with a Team `victim-org/admins` present in `Shipit.github_teams`):

1. Attacker sends an unauthenticated POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": {"id": 999999, "name": "Admins", "slug": "admins", "url": "https://api.github.com/teams/999999"},
  "organization": {"login": "OrgB"},
  "member": {"login": "attacker-login"},
  "repository": {"owner": {"login": "OrgA"}}
}
```
2. `WebhooksController#verify_signature` computes `repository_owner = "OrgA"` (from the injected `repository.owner.login`), fetches `Shipit.github(organization: "OrgA")`, and `verify_webhook_signature` returns `true` immediately because `OrgA` has no `webhook_secret` — see [13](#0-12) .
3. `MembershipHandler#process` then runs against `params.organization.login = "OrgB"`, creating/finding the `Team` with `github_id: 999999` and `organization: "OrgB"`, and adds `attacker-login` as a member: [9](#0-8) .
4. If this Team's `organization`/`slug` matches one referenced by `Shipit.github_teams`, the attacker's `User` record now satisfies `authorized?`, without ever having a valid signature checked against `OrgB`'s real `webhook_secret`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/team.rb (L17-21)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
