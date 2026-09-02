### Title
Membership webhook organization/authentication mismatch enables cross-organization `Shipit.github_teams` escalation - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to verify the request against using one payload field, while `MembershipHandler` uses a different (independently attacker-controlled) set of fields to decide which `Team`/`Membership` records get mutated. Because the engine's authorization gate (`Shipit.github_teams`) is global and keyed off `Team#organization`/`Membership`, a payload that is only cryptographically "authenticated" for a weak/unsecured organization can still mutate team membership belonging to a completely different, security-relevant organization.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and thus the secret used to validate `X-Hub-Signature`) using `repository_owner`, computed straight from the untrusted JSON body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` trivially passes when the resolved organization has no `webhook_secret` configured: [3](#0-2) 

Per-organization `webhook_secret` being blank is a **documented, supported configuration**, not a misconfiguration: [4](#0-3) [5](#0-4) 

Once the request clears `verify_signature`, `MembershipHandler` acts using an entirely separate field from the same JSON body — `organization.login` and `team.id` — to find/create the `Team` and add/remove the `member`: [6](#0-5) 

Nothing enforces that the organization whose secret validated the request equals the `organization.login`/`team.id` the handler operates on. `Team#organization` is only set on first creation (`find_or_create_by!`), so for any team already tracked by Shipit (e.g. one of `Shipit.github_teams`), the `team.id` alone is sufficient to target it, regardless of which org secret validated the request: [7](#0-6) 

`Shipit.github` resolves per-organization secrets only when the engine is configured in "multiple GitHub applications" mode; the `organization:` argument is otherwise ignored: [8](#0-7) 

`Shipit.github_teams` and `User#authorized?` are **global**, application-wide authorization gates that check membership regardless of which organization installed which GitHub App: [9](#0-8) [10](#0-9) 

**Equality that should hold but doesn't:** `organization(secret) used to authenticate the request == organization/team the handler mutates`. The controller derives the former from `repository.owner.login` (falling back to `organization.login` only when `repository` is absent), while the handler derives the latter independently from `organization.login` + `team.id`, with no cross-check tying the two together.

### Impact Explanation
In a multi-organization Shipit deployment (documented feature), if any one configured organization has a blank `webhook_secret` (a documented valid config) or its secret is otherwise known/weaker than another organization's, an attacker can forge a `membership` event that authenticates against that weak organization yet, via the `organization`/`team.id` fields, adds an arbitrary GitHub login as a member of a `Team` that is part of `Shipit.github_teams` — the exact team-based authorization check gating access to the entire Shipit application (`app/controllers/concerns/shipit/authentication.rb`, `User#authorized?`). This is an escalation into `Shipit.github_teams` authorization, which is explicitly a High-severity impact for this engine, since it lets an attacker bypass the application's access control without possessing the target organization's actual GitHub App credentials.

### Likelihood Explanation
Requires the "Using Multiple GitHub Applications" configuration (documented, plausible for organizations deploying Shipit across several GitHub orgs) and at least one configured organization with a weaker/absent `webhook_secret`, plus knowledge of an existing `Team`'s GitHub `id` (obtainable via GitHub's public/team API) that is part of `Shipit.github_teams`. This is a design gap rather than a one-off typo, and is reachable purely by crafting an HTTP request to the public `/webhooks` endpoint — no session, API token, or GitHub App private key is required.

### Recommendation
In `WebhooksController#verify_signature` and in each webhook `Handler`, resolve and act on the *same* organization identifier. Concretely: bind `MembershipHandler` (and any other handler keying off `organization.login`) to the organization that was actually used to select/verify the webhook signature, and reject the event if `organization.login` (or `repository.owner.login`) does not match the organization resolved during signature verification. Alternatively, disallow blank `webhook_secret` for any organization when running in multi-organization mode, since a single unsecured org otherwise weakens the whole deployment's team-based authorization boundary.

### Proof of Concept
1. Deploy Shipit with multiple GitHub organizations configured (`config/secrets.yml` using the `github.<org>` schema), where `OrgWeak` has `webhook_secret:` left blank (a documented valid config) and `OrgTarget` has a properly configured `Team` referenced in `Shipit.github_teams` (e.g. `github_id: 123`).
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": 123, "name": "Developers", "slug": "developers", "url": "https://example.com" },
  "organization": { "login": "OrgTarget" },
  "member": { "login": "attacker" },
  "repository": { "owner": { "login": "OrgWeak" } }
}
```
No `X-Hub-Signature` (or any value) is required because `OrgWeak` has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally.
3. `WebhooksController#verify_signature` resolves `repository_owner` to `"OrgWeak"`, verification passes trivially, and `MembershipHandler#process` runs using `organization.login == "OrgTarget"` and `team.id == 123`, adding `attacker` as a member of `OrgTarget`'s `Team#123`.
4. If that team is part of `Shipit.github_teams`, `attacker`'s corresponding `User#authorized?` now returns `true`, granting them access to the entire Shipit UI/API gated by that authorization check — without ever knowing `OrgTarget`'s real webhook secret.

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-47)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandler < Handler
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
      end
    end
  end
end
```

**File:** app/models/shipit/team.rb (L17-27)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end

      def fetch_and_create_from_github(organization, slug)
        return unless github_team = find_team_on_github(organization, slug)

        create!(github_team:, organization:)
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
