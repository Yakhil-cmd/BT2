### Title
Webhook organization used for signature verification is decoupled from the organization whose data handlers write, allowing cross-organization forgery of `membership` events - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
In a multi-GitHub-App Shipit deployment (the officially documented "Using Multiple Github Applications" configuration), `WebhooksController#verify_signature` picks the GitHub App/secret used to validate `X-Hub-Signature` from `repository.owner.login` (falling back to `organization.login`) taken from the *same, single* incoming JSON body that the `MembershipHandler` later trusts for `organization.login`/`team`/`member`. Because `MembershipHandler` never reads or validates `repository`, an attacker can inject an unused, spoofed `repository.owner.login` field solely to steer signature verification to a weaker/known-secret organization, while the fields that are actually acted upon (`organization`, `team`, `member`) target a victim organization/team. This breaks the equality "organization that authenticated the request == organization whose data is written."

### Finding Description
`WebhooksController#verify_signature` selects the app/secret purely from attacker-controlled JSON content: [1](#0-0) [2](#0-1) 

`repository_owner` prioritizes `repository.owner.login` over `organization.login`. This value is fed into `Shipit.github(organization: repository_owner)`, which resolves a per-organization `webhook_secret` in multi-app installations: [3](#0-2) [4](#0-3) 

Note that `verify_webhook_signature` returns `true` unconditionally when the resolved app has no `webhook_secret` configured (the setup docs mark it "optional").

Once the signature "verification" passes (using whichever org it resolved to), the *entire raw body* is dispatched, unmodified, to the event handler for the declared `X-Github-Event` type: [5](#0-4) 

For a `membership` event, `MembershipHandler` only requires and consumes `action`, `team`, `organization`, and `member` — it never references `repository` at all: [6](#0-5) [7](#0-6) 

`find_or_create_team!` looks up an existing `Team` by `github_id` (from the attacker-controlled `team.id`), and if that `github_id` matches an already-legitimately-synced team, the *existing* `Team` row is reused (not recreated), and `team.add_member(member)` adds an attacker-chosen GitHub login to it. Membership in these teams is exactly what governs application authorization: [8](#0-7) [9](#0-8) 

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by verify_signature (repository.owner.login)` **==** `organization/team whose membership is mutated by the handler (organization.login / team.id)`

Because `repository` is entirely orthogonal to what `MembershipHandler` uses, an attacker can set `repository.owner.login` to any organization onboarded to the same Shipit instance that has a weak/no `webhook_secret`, causing the request to be "verified," while the real `organization`/`team`/`member` fields target a different, strictly-secured organization's authorized team.

### Impact Explanation
This directly matches the High-impact bucket "escalation into `Shipit.github_teams` authorization": by forging a `membership` "added" event with a real (but attacker-known) team `github_id` belonging to a team listed in `Shipit.github_teams`, and by picking a weak-secret co-tenant organization purely for `repository.owner.login`, an unprivileged external attacker can add an arbitrary GitHub login (including their own) as a member of an authorized `Team` row in Shipit's database, granting themselves `User#authorized?` and full access to the Shipit application (repositories, deploys, tasks) without ever needing legitimate GitHub org membership or a valid signature over the real organization's data.

### Likelihood Explanation
This requires the documented multi-GitHub-App configuration (multiple organizations, each with its own optional `webhook_secret`) and requires the attacker to control or know of at least one onboarded organization whose `webhook_secret` is unset or otherwise known (the setup docs explicitly mark it optional, and it is plausible for smaller/less-sensitive co-tenant orgs on a shared Shipit instance to omit it). It also requires knowledge of the numeric GitHub `team.id` of the target authorized team, which is discoverable via the GitHub API by any member with team visibility, or brute-forceable since it's a small integer namespace. This is a realistic configuration and requires no privileged Shipit credentials, session, or GitHub App key — only the ability to send an unauthenticated HTTP POST to `/webhooks`.

### Recommendation
- Do not use payload-derived fields to select which secret verifies that same payload. Route verification through a stable, out-of-band organization identifier (e.g., a webhook URL path segment or the App installation ID resolved server-side) rather than `params.dig('repository', 'owner', 'login')`.
- After signature verification succeeds for organization `O`, enforce that every organization-bearing field consumed by handlers (`repository.owner.login`, `organization.login`) equals `O`; reject the event otherwise.
- Require `webhook_secret` to be present for all configured GitHub Apps/organizations (fail closed rather than `return true unless webhook_secret`).
- Consider validating in `Team.find_or_create_by!` that `github_id` collisions are also constrained by matching `organization`, to prevent cross-organization team hijacking via id reuse.

### Proof of Concept
Preconditions: Shipit configured with two GitHub Apps, `victim-org` (has `webhook_secret` and `oauth.teams: ["victim-org/developers"]`) and `attacker-org` (onboarded, but `webhook_secret` left blank as the docs mark it optional).

```
POST /webhooks HTTP/1.1
X-Github-Event: membership
X-Hub-Signature: sha1=0000000000000000000000000000000000000000   # arbitrary/garbage, irrelevant

{
  "action": "added",
  "repository": { "owner": { "login": "attacker-org" } },
  "organization": { "login": "victim-org" },
  "team": {
    "id": 123456,          # real github_id of the already-synced "victim-org/developers" Team row
    "name": "Developers",
    "slug": "developers",
    "url": "https://api.github.com/teams/123456"
  },
  "member": { "login": "attacker-github-login" }
}
```

- `WebhooksController#repository_owner` returns `"attacker-org"` (from the injected `repository` block), so `Shipit.github(organization: "attacker-org")` resolves the app with no `webhook_secret` → `verify_webhook_signature` returns `true` regardless of the bogus `X-Hub-Signature`.
- `create` dispatches the full payload to `MembershipHandler`, which ignores `repository`, finds the existing `Team` (github_id 123456, `victim-org/developers`), and calls `team.add_member(User.find_or_create_by_login!("attacker-github-login"))`.
- `attacker-github-login`'s Shipit `User#authorized?` now returns `true` via `Shipit.github_teams` membership, granting full access to the Shipit instance.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
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
