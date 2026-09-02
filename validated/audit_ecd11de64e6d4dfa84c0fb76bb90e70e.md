### Title
Membership webhook signature is verified against an organization selected from the unverified payload, allowing team-authorization forgery when any configured GitHub org has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects *which* GitHub App/secret to verify the incoming signature against by reading `repository_owner` straight out of the still-unauthenticated JSON body, then hands the *entire* body (including the `team`/`organization`/`member` fields consumed later by `MembershipHandler`) to the event handler. Because `verify_webhook_signature` treats a blank `webhook_secret` as automatically verified, and Shipit explicitly supports multi-organization configuration where each org can independently omit its `webhook_secret`, an attacker can pick the org used purely for signature selection while the handler logic actually acts on unrelated `team`/`organization` identifiers taken from the same forged payload.

### Finding Description
`verify_signature` derives `repository_owner` from the raw, unverified body: [1](#0-0) [2](#0-1) 

For a `membership` event there is no `repository` key, so `repository_owner` falls back to `params.dig('organization', 'login')` — an attacker-controlled field. This value selects the `GitHubApp` instance/secret used to verify the signature: [3](#0-2) 

`verify_webhook_signature` short-circuits to `true` whenever the selected org's `webhook_secret` is blank: [4](#0-3) 

Shipit's own multi-org configuration schema documents `webhook_secret` as optional per organization: [5](#0-4) 

Once "verified," the full (still forged) body is dispatched unchanged to `MembershipHandler`, which trusts `params.team.id`, `params.organization.login`, and `params.member.login` independently of whatever org key was used for verification: [6](#0-5) 

The team is looked up only by the numeric `github_id`. `organization` is only written when the `Team` record is first created; on any subsequent event for an already-known team, `organization.login`/the org used for signature selection has no bearing on which team gets the membership write. Teams referenced in `Shipit.oauth.teams` back the authorization surface: [7](#0-6) 

**Binding broken:** *the organization whose secret authenticated the request* (`repository_owner`/`organization.login` used only to pick the verifying `GitHubApp`) is never required to equal *the organization/team the membership write actually targets* (`params.team.id`, resolved independently of the verifying org). Because one configured org can validly have no `webhook_secret` (a documented, supported configuration), a request can be fully "verified" while writing to a completely different org's team.

### Impact Explanation
An attacker who forges a `membership` webhook — selecting, via the `organization.login` field, any configured org that has no `webhook_secret` set, while setting `team.id` to the numeric GitHub team ID of a privileged team referenced in `Shipit.oauth.teams` and `member.login` to their own GitHub username — causes `MembershipHandler#process` to call `team.add_member(member)` and grant themselves membership in that team without ever presenting a valid HMAC for the org that actually owns the privileged team. This is a direct escalation into `Shipit.github_teams` authorization, matching the High-impact category defined for this engine.

### Likelihood Explanation
Requires only: (1) a Shipit deployment using the documented multi-organization `github:` config schema, and (2) at least one configured org left without a `webhook_secret` (explicitly called "optional" in `docs/setup.md`/example secrets files). Numeric GitHub team IDs are discoverable via the public GitHub API for any team the attacker can see, so no secret material needs to be known. No prior Shipit session, `ApiClient` token, or repository write access is required — the request is an unauthenticated POST to `/webhooks`.

### Recommendation
Do not select the verifying organization/secret from unverified request content. Either require a `webhook_secret` for every configured organization (reject verification instead of auto-passing when blank), or bind the organization used to select the verification key to the same identifier the handler subsequently uses to scope the write (e.g., re-validate that `team.organization`/`params.organization.login` matches the org whose secret verified the request, and re-check on every `find_or_create_team!` call, not just on creation).

### Proof of Concept
1. Deploy Shipit with multi-org config: `orgA` (privileged, has team `T` with GitHub `github_id: 555` listed in `oauth.teams`) and `orgB` (configured but with no `webhook_secret`).
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": 555, "name": "Deployers", "slug": "deployers", "url": "https://x" },
  "organization": { "login": "orgB" },
  "member": { "login": "attacker-handle" }
}
```
No `X-Hub-Signature` (or any garbage value) is required, since `Shipit.github(organization: "orgB")` resolves an org with a blank `webhook_secret`, causing `verify_webhook_signature` to return `true` per [8](#0-7) .
3. `MembershipHandler` finds team `555` (`orgA`'s privileged team) by `github_id` and adds `attacker-handle` as a member, per [9](#0-8) , granting the attacker `Shipit.github_teams`-backed authorization without ever authenticating against `orgA`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
