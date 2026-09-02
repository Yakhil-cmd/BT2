Confirmed the full chain. This gives a concrete, in-scope escalation path into `Shipit.github_teams` authorization via the webhook signature-selection binding.

### Title
Webhook signature verification key is selected from the unauthenticated payload, allowing forged `membership` events to grant `Shipit.github_teams` access when any configured org has no `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` chooses which GitHub App/organization's `webhook_secret` to verify the request against by reading `repository.owner.login` / `organization.login` straight out of the still-unverified JSON body, and `GitHubApp#verify_webhook_signature` treats a blank `webhook_secret` as "always verified." Because Shipit explicitly supports multi-organization configs where `webhook_secret` is documented as optional per org, an attacker can pick the unprotected organization's name for `organization.login` in a `membership` webhook and have it accepted with **no valid signature at all**, letting them add arbitrary GitHub users to a `Team` used for `Shipit.github_teams` authorization.

### Finding Description
The equality binding the engine is supposed to enforce is:

`organization whose webhook_secret cryptographically authenticated this request == organization whose Team/membership data this request is allowed to mutate`

`verify_signature` breaks this binding because the organization used to pick the verification key comes from inside the same untrusted payload it's about to verify: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever that organization's `webhook_secret` is blank: [3](#0-2) 

Multi-org setups are an explicitly documented, supported configuration, and `webhook_secret` is documented as optional per app/org: [4](#0-3) [5](#0-4) 

`Shipit.github` resolves the config per-organization with `github_app_config`, and caches one `GitHubApp` instance per organization key, each with its own independently-blank-or-not `webhook_secret`: [6](#0-5) 

If the attacker names an organization in the payload whose configured `webhook_secret` is nil/blank (a state the app's own template and sample secrets files leave as the default), `verify_signature` will pass unconditionally regardless of the `X-Hub-Signature` header's actual content: [7](#0-6) [8](#0-7) 

Once past `verify_signature`, `MembershipHandler#process` trusts the payload's `organization.login`, `team`, and `member.login` fields to create/find a `Team` and add or remove members from it: [9](#0-8) 

That `Team` is exactly what gates access application-wide: `User#authorized?` checks membership against `Shipit.github_teams`, and `Shipit.github_teams` is built from `Team.find_or_create_by_handle` using the organization/slug pulled straight from webhook-created `Team` rows: [10](#0-9) [11](#0-10) 
`force_github_authentication` is what enforces this team check on every controller in the engine: [12](#0-11) 

### Impact Explanation
An unauthenticated attacker who knows (or guesses, e.g. from public docs/`github_organizations`) the name of any configured organization lacking a `webhook_secret` can forge a `membership` webhook `action: added` event, adding their own or an arbitrary GitHub login to the `Team` backing `Shipit.oauth.teams`. Since `current_user.authorized?` is computed purely from `teams.where(id: Shipit.github_teams.map(&:id)).exists?`, this directly escalates an attacker's already-existing (unrelated) GitHub-authenticated session into full `Shipit.github_teams` authorization — the explicit High-severity criterion "escalation into `Shipit.github_teams` authorization." From there the attacker gains normal authenticated access to trigger deploys, rollbacks, and merges through the rest of the engine.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment (documented, supported configuration), and (2) at least one configured organization with a blank `webhook_secret` — which is the literal default in the shipped `template.rb`, `config/secrets.development.shopify.yml`, and is explicitly called "optional" in `docs/setup.md`. Any operator who follows the docs/template as-is for a secondary org, or simply omits an optional secret, is exposed. No credentials, tokens, or prior repository access are needed — only knowledge of the target org's name and a POST to the public `/webhooks` endpoint.

### Recommendation
- Never derive the signature-verification key from fields inside the unverified request body. Instead, verify the payload against every configured organization's secret (or require the app installation/organization to be identified out-of-band, e.g. via a per-org webhook URL segment) and only proceed if at least one verification succeeds.
- Stop treating a blank `webhook_secret` as automatically verified; either require `webhook_secret` for every configured organization or reject requests when none is configured, rather than silently accepting unsigned payloads.
- Cross-check that the `organization`/`repository.owner` claimed inside the payload actually matches the organization whose secret produced a valid signature before dispatching to any handler.

### Proof of Concept
1. Deploy Shipit with two organizations configured per `docs/setup.md`'s "Using Multiple Github Applications" section: `orgA` (has `webhook_secret` set, restricts login via `oauth.teams: [orgA/admins]`) and `orgB` (installed for convenience, `webhook_secret` left blank, as in the shipped `template.rb`/`secrets.development.shopify.yml` defaults).
2. As an unauthenticated attacker with no valid `X-Hub-Signature`, POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": {"id": 999, "name": "admins", "slug": "admins", "url": "https://api.github.com/orgs/orgA/teams/admins"},
  "organization": {"login": "orgB"},
  "member": {"login": "attacker-github-login"}
}
```
3. `verify_signature` resolves `Shipit.github(organization: 'orgB')`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the (missing/garbage) `X-Hub-Signature` header.
4. `MembershipHandler#process` creates/finds `Team#github_id=999` and adds `attacker-github-login` as a member.
5. If `orgA/admins` is (or later becomes, or collides by `github_id`) one of `Shipit.github_teams`, `User#authorized?` for `attacker-github-login` now returns `true`, bypassing the team-restricted access check in `force_github_authentication` on every controller in the engine.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-24)
```ruby
    def verify_signature
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

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
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

**File:** template.rb (L97-114)
```ruby
    production:
      app_name: My Shipit
      secret_key_base: <%= ENV['SECRET_KEY_BASE'] %>
      host: <%= ENV['SHIPIT_HOST'] %>
      redis_url: <%= ENV['REDIS_URL'] %>
      github:
        domain: # defaults to github.com
        app_id: <%= ENV['GITHUB_APP_ID'] %>
        installation_id: <%= ENV['GITHUB_INSTALLATION_ID'] %>
        webhook_secret:
        private_key:
        oauth:
          id: <%= ENV['GITHUB_OAUTH_ID'] %>
          secret: <%= ENV['GITHUB_OAUTH_SECRET'] %>
          # teams: MyOrg/developers # Enable this setting to restrict access to only the member of a team
      env:
        # SSH_AUTH_SOCK: /foo/bar # You can set environment variable that will be present during deploys.
  CODE
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-44)
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
