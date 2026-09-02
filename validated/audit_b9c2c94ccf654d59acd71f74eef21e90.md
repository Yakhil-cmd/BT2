### Title
`MembershipHandler#find_or_create_team!` resolves teams by global `github_id` without binding to the webhook-verified organization, letting a webhook signed by any configured (even unprivileged) tenant mutate a different, privileged `Team`'s membership - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` only proves that the request body was signed by the GitHub App configured for `params.organization.login` (or `params.dig('repository','owner','login')`, absent on `membership` events). `MembershipHandler#find_or_create_team!` then looks up `Team.find_or_create_by!(github_id: params.team.id)` with no check that the found team's `organization` matches the verified `params.organization.login`. In a multi-tenant Shipit deployment (explicitly supported, see `docs/setup.md` "Using Multiple Github Applications"), a tenant that owns its own GitHub App/org (and therefore genuinely knows its own `webhook_secret`) can sign an arbitrary `membership` payload naming a `team.id` that collides with a different, privileged tenant's `Team#github_id`, causing the handler to add an attacker-chosen `member.login` to that unrelated, privileged team.

### Finding Description
The broken binding: `verified_organization (params.organization.login, checked against Shipit.github(organization: verified_organization).webhook_secret) == team.organization (the organization owning the Team record mutated by the handler)`.

Trace:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-38`) computes `repository_owner` via `params.dig('repository','owner','login') || params.dig('organization','login')`. GitHub `membership` events carry no top-level `repository` key, so `repository_owner` resolves to the attacker-supplied `organization.login`. Signature verification (`GitHubApp#verify_webhook_signature`, `lib/shipit/github_app.rb:76-83`) succeeds because the attacker signs with the `webhook_secret` of the org/App they legitimately own and Shipit is configured to trust (multi-org config, `lib/shipit.rb:170-200`, `docs/setup.md:182-209`).
- `MembershipHandler#process` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`) calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login ... }` (`app/models/shipit/webhooks/handlers/membership_handler.rb:38-43`). `find_or_create_by!`'s block only runs when a **new** record is being built; if a `Team` with that `github_id` already exists (e.g. a privileged team fixture like `shopify_developers` with `github_id: 1`), the existing record is returned untouched — `team.organization` is never checked or reassigned to the verified org.
- Back in `process`, `member = User.find_or_create_by_login!(params.member.login)` uses the attacker-controlled `member.login`, and `team.add_member(member)` (`app/models/shipit/team.rb:41-43`) appends that user to the **found** (privileged) `Team`'s `members` association — regardless of the mismatch between the verified organization and the team's real `organization`.
- `User#authorized?` (`app/models/shipit/user.rb:80-82`) grants access whenever `teams.where(id: Shipit.github_teams.map(&:id)).exists?`, so being added to a `Team` referenced in `Shipit.github_teams` directly satisfies authorization.

No existing guard closes this gap: `verify_signature` only authenticates *which org's secret signed this specific request*, not that the payload's `team`/`organization` fields are self-consistent with a team actually owned by that org; `drop_unhandled_event` and the `ExplicitParameters` schema only validate presence/types, not cross-organization ownership; `find_or_create_by!` never re-validates `organization` on the found branch.

### Impact Explanation
A tenant/attacker who legitimately controls one configured (but unprivileged) GitHub organization in a multi-org Shipit deployment can add their own GitHub login to any pre-existing `Team` record whose numeric `github_id` they can predict or discover (team IDs are visible via the GitHub API), including teams listed in `Shipit.github_teams`. This directly satisfies `User#authorized?`, escalating an unprivileged attacker into Shipit's privileged-team authorization — matching the High severity category "escalation into `Shipit.github_teams` authorization." The attack is repeatable against any `Team` record whose `github_id` is known, and is not confined to the attacker's own tenant/org — it crosses tenant boundaries, which is the core provenance violation.

### Likelihood Explanation
Requires a Shipit deployment using the multi-organization GitHub App configuration (documented, supported feature) where the attacker legitimately owns/administers one of the configured, less-privileged organizations (and thus genuinely possesses that org's own `webhook_secret`), plus knowledge of the target privileged `Team`'s `github_id` (learnable via GitHub's public/API team metadata). No Shipit secrets, sessions, or API tokens are needed. Cost is low: one crafted POST to `/webhooks` with a valid HMAC signature computed from a secret the attacker legitimately owns.

### Recommendation
Scope the `Team` lookup by both `github_id` and `organization`, and reject/raise rather than silently reusing a record when `github_id` matches but `organization` differs from the webhook-verified organization:
```ruby
def find_or_create_team!
  team = Team.find_by(github_id: params.team.id)
  if team && team.organization != params.organization.login
    raise ArgumentError, "github_id #{params.team.id} belongs to a different organization"
  end
  Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login) do |t|
    t.github_team = params.team
  end
end
```

### Proof of Concept
minitest (`test/controllers/webhooks_controller_test.rb`-style):
```ruby
test ":membership from a different org cannot hijack a privileged team's membership" do
  privileged_team = shipit_teams(:shopify_developers) # github_id: 1, organization: 'shopify'
  Shipit.stubs(:github_teams).returns([privileged_team])

  @request.headers['X-Github-Event'] = 'membership'
  attacker_payload = {
    action: 'added',
    team: { id: privileged_team.github_id, name: 'x', slug: 'x', url: 'https://example.com' },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker' }
  }.to_json

  Shipit.github(organization: 'attacker-org').expects(:verify_webhook_signature).returns(true)

  post :create, body: attacker_payload, as: :json

  privileged_team.reload
  attacker = User.find_by(login: 'attacker')
  # Binding check: verified org ('attacker-org') != team.organization ('shopify')
  refute_equal 'attacker-org', privileged_team.organization
  # Vulnerability: attacker was still added to the privileged team
  refute_includes privileged_team.members, attacker # should hold post-fix; currently fails, proving the bug
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** app/models/shipit/team.rb (L41-58)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end

    def refresh_members!
      github_api = Shipit.github(organization:).api
      github_members = Shipit::OctokitIterator.new(github_api.get(api_url).rels[:members])
      members = github_members.map { |u| User.find_or_create_from_github(u) }
      self.members = members
      save!
    end

    def github_team=(github_team)
      self.name = github_team.name
      self.slug = github_team.slug
      self.api_url = github_team.url
      self.github_id = github_team.id
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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
