### Title
Membership webhook handler grants team membership without re-validating that the authenticated GitHub organization owns the referenced team ID - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
Shipit supports multi-tenant GitHub App configuration, where `Shipit.github(organization:)` selects an organization-specific `webhook_secret` to verify inbound webhooks [1](#0-0) . `WebhooksController#verify_signature` derives the organization used for signature verification purely from the request payload (`repository.owner.login` or `organization.login`), not from any independently trusted source [2](#0-1) . The `membership` handler then trusts the payload's `team.id` to look up (or create) a `Team` record and grant membership, without ever confirming that `team.id` actually belongs to the organization that was cryptographically authenticated for this request.

### Finding Description
`MembershipHandler#find_or_create_team!` does:

```ruby
Team.find_or_create_by!(github_id: params.team.id) do |team|
  team.github_team = params.team
  team.organization = params.organization.login
end
``` [3](#0-2) 

The `organization` attribute is only assigned inside the `find_or_create_by!` block, which Rails only executes when a **new** record is built. If a `Team` row with that `github_id` already exists (created previously through a legitimate sync for a different organization, e.g. via `Team.find_or_create_by_handle` / `rake teams:fetch` [4](#0-3) ), the existing record is returned as-is and `team.add_member(member)` is called unconditionally [5](#0-4) .

Crucially, the webhook's authenticity is bound only to the `organization`/`repository` field used to pick the per-org `webhook_secret` [6](#0-5) , `path="lib/shipit/github_app.rb" start="76" end="83"`. Nothing ties the numeric `team.id` in the payload to that same organization. This creates exactly the "escrowPortion vs escrowPool" style decoupling: one field (`organization.login`) is what gets verified/authenticated, while a different field (`team.id`) is what actually gets acted upon to grant privilege — and the two are never cross-checked when the team record already exists.

`Shipit.github_teams` — the set of teams used to gate access to the whole application — is built from configured team handles and their `Team` IDs [7](#0-6) , and `User#authorized?` checks membership against exactly those team IDs [8](#0-7) .

### Impact Explanation
An organization that legitimately owns its own webhook secret (i.e. an org admin who configured their own GitHub App/webhook secret for this shared Shipit instance) can sign an arbitrary `membership` payload themselves. `verify_webhook_signature` will pass because it only checks the HMAC against the secret belonging to whichever organization the attacker names in the payload (their own org) [9](#0-8) . Inside that payload they can set `team.id` to the numeric GitHub ID of a **different**, privileged team (e.g. one listed in `Shipit.github_teams`) and `member.login` to an arbitrary login, with `action: "added"`. Because the team lookup only keys on `github_id` and does not re-validate `organization`, the handler adds that (possibly attacker-controlled) user into the privileged team, escalating them into `Shipit.github_teams` authorization and granting full access to the Shipit UI/API for stacks the attacker should not control. This matches the explicitly listed High-impact category "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Exploitation requires the attacker to control (or know) a valid webhook secret for *some* organization configured on the shared Shipit instance (a realistic scenario for a Shipit deployment serving multiple organizations/tenants, where org admins configure their own GitHub App). It also requires the attacker to know/guess the numeric `github_id` of the target team, which is not secret and is discoverable through the GitHub API for any team the attacker can enumerate. No repository write access, Shipit session, or `ApiClient` token is required — only the ability to sign a webhook payload with one's own organization's secret.

### Recommendation
When resolving the team by `github_id`, always verify that `team.organization == params.organization.login` (case-insensitively) before applying `team.add_member`/`team.members.delete`, and raise/reject the event if there's a mismatch. Alternatively, look up teams scoped by `(organization, github_id)` instead of `github_id` alone, so that a payload authenticated for organization A can never mutate a team belonging to organization B.

### Proof of Concept
1. Shipit is configured with `secrets.github` containing per-organization entries `attacker-org` and `victim-org`, each with its own `webhook_secret` (multi-tenant setup, matching `github_app_config` in `lib/shipit.rb` lines 196-200).
2. `victim-org` has previously triggered a real `membership` event, so a `Team` record exists with `github_id = 555, organization = "victim-org"`. This team's id is included in `Shipit.github_teams`.
3. Attacker, who legitimately administers `attacker-org` and therefore knows `attacker-org`'s `webhook_secret`, crafts:
```json
{
  "action": "added",
  "team": { "id": 555, "name": "Whatever", "slug": "whatever", "url": "https://api.github.com/teams/555" },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-login" },
  "repository": { "owner": { "login": "attacker-org" }, ... }
}
```
and signs it with `attacker-org`'s `webhook_secret`, sending it as `X-Github-Event: membership` to `/webhooks`.
4. `verify_signature` succeeds because `repository_owner` resolves to `attacker-org`, matching the secret used [10](#0-9) .
5. `MembershipHandler#find_or_create_team!` finds the existing `Team(github_id: 555)` belonging to `victim-org` and returns it unchanged (no re-validation of `organization`) [3](#0-2) ; `team.add_member(User.find_or_create_by_login!("attacker-login"))` executes, adding `attacker-login` to `victim-org`'s privileged team.
6. `attacker-login` now passes `User#authorized?` via `Shipit.github_teams` and gains access to Shipit-managed stacks/deploys tied to `victim-org`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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
