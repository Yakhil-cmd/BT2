### Title
Unsigned/unverified webhook events (when `webhook_secret` is unset) let an unprivileged attacker forge `membership` events and self-grant `Shipit.github_teams` authorization - (File: `lib/shipit/github_app.rb`, `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`GithubApp#verify_webhook_signature` silently treats "no configured secret" as "signature valid," so any organization entry in `config/secrets.yml` that omits `webhook_secret` (explicitly documented as *optional* in `docs/setup.md`) accepts **unsigned** webhook deliveries. `WebhooksController#verify_signature` selects which organization's app/secret to check purely from the attacker-suppliable JSON body (`repository.owner.login` / `organization.login`), and then dispatches the same unauthenticated body straight to `Shipit::Webhooks::Handlers::MembershipHandler`, which mutates `Team`/`Membership` records — the exact records `User#authorized?` and `Shipit.github_teams` rely on for authorization.

### Finding Description
`GithubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank: [1](#0-0) 

The organization used to resolve *which* `GithubApp`/secret applies is read straight out of the unauthenticated request body: [2](#0-1) 

`webhook_secret` is explicitly documented as optional when creating the GitHub App, and multiple shipped/example configs (`config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`) leave it as `nil`: [3](#0-2) 

Once the request clears (or is never actually checked by) `verify_signature`, the raw JSON body is dispatched to registered handlers, including `MembershipHandler`, without any other authentication: [4](#0-3) 

`MembershipHandler#process` trusts the payload's `team`, `organization`, and `member.login` fields to create/find a `Team` and unconditionally add the named user as a member when `action == 'added'`: [5](#0-4) 

That `Team`/`Membership` binding is exactly what gates the whole application: `User#authorized?` checks membership in `Shipit.github_teams`, and `Shipit.github_teams` is derived from `github.oauth.teams` config, matched against `Team` records by `organization`/`slug`: [6](#0-5) [7](#0-6) 

This is a direct analog of the reported bug class: the binding that should hold — *the organization whose webhook signature was actually verified* (or "verified" only in the trivial `return true unless webhook_secret` sense) *must equal the organization/team whose membership record is written* — is broken. The controller verifies (or no-ops on) an organization identity taken from attacker-controlled JSON, then hands the same untrusted JSON to a handler that writes authorization-relevant state (`Team`, `Membership`) keyed off further attacker-controlled JSON fields (`team.id`, `team.slug`, `member.login`, `organization.login`) with no cross-check against the GitHub App installation that's supposed to be the source of truth.

### Impact Explanation
If any configured organization in `Shipit.github` config has no `webhook_secret` (a state the project's own setup docs call "optional" and its own example/dummy configs ship with), an unauthenticated network attacker can POST a crafted `membership` webhook naming any existing (or self-created) OAuth-restricting `Team`/organization, and any GitHub login (including their own), with `action: 'added'`. This creates a `Membership` row linking that login to the team backing `Shipit.github_teams`. If the attacker then completes normal GitHub OAuth login as that login (a login they control), `User#authorized?` returns true and they gain full application access — an escalation into `Shipit.github_teams` authorization, one of the explicitly accepted High-severity impacts, without ever holding a Shipit session, API token, or repository write access.

### Likelihood Explanation
Likelihood is conditioned on an operator deploying the engine with `webhook_secret` unset for an organization, which the maintainers' own documentation and shipped example/dummy secrets files treat as a normal, supported configuration ("Webhook secret (optional)"), so this is not "not mounting the engine as documented" — it is the documented default path. Given that condition, exploitation requires only a single unauthenticated HTTP POST with a crafted JSON body; no secret, token, or prior access is needed.

### Recommendation
- Do not treat a missing `webhook_secret` as automatic verification success; require an explicit, operator-acknowledged "unsigned webhooks allowed" opt-in, or refuse to process authorization-mutating events (`membership`) at all when no secret is configured.
- Cross-check that the organization used to select the verifying `GithubApp` matches the organization actually referenced in the payload used by the handler (`team.organization` / `member`), rather than trusting the same untrusted JSON on both sides of the binding.
- For `MembershipHandler`, refetch team membership from the GitHub API (as `Team#refresh_members!` already does) rather than trusting webhook payload fields to mutate `Membership` rows that gate authorization.

### Proof of Concept
1. Deploy Shipit with an organization entry in `config/secrets.yml` that has `webhook_secret` unset (as shown in `config/secrets.development.shopify.yml` / `test/dummy/config/secrets_double_github_app.yml`).
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": 1, "name": "Shopify Developers", "slug": "developers", "url": "https://api.github.com/teams/1" },
  "organization": { "login": "shopify" },
  "member": { "login": "attacker-github-login" }
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "shopify").verify_webhook_signature(...)`, which returns `true` immediately because `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`) — no valid `X-Hub-Signature` header is needed.
4. `Shipit::Webhooks.for_event('membership')` dispatches to `MembershipHandler#process`, which creates/finds the `Team` (matching an OAuth-restricting team if `slug`/`organization` are chosen to match `Shipit.github_teams`) and adds `attacker-github-login` as a member (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`).
5. Attacker completes GitHub OAuth login as `attacker-github-login`; `User#authorized?` now returns `true` (`app/models/shipit/user.rb:80-82`), granting them full authenticated access to the Shipit instance.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```
