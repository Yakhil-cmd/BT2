Found a genuine binding-break analog in the `MembershipHandler`: the GitHub organization used to authenticate the webhook signature is never checked against the organization used to grant `Shipit.github_teams` team membership carried by the same payload.

### Title
Membership webhook grants team access based on an unverified `organization.login` field never bound to the signing organization - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the request against based on `repository_owner`, which falls back to `params.dig('organization', 'login')` when no `repository` key is present. `MembershipHandler`, however, trusts this same unverified `organization.login` value to create/attach a `Team` record and grant `Membership` rows that directly control `Shipit.github_teams` authorization (`User#authorized?`). Because signature verification is only cryptographically strong when a `webhook_secret` is configured for *every* configured organization in `config/secrets.yml`, and because the field selecting "which organization's secret to check" is the very same attacker-influenced field used later to grant membership, a single-tenant misconfiguration (one org configured without a `webhook_secret`, which the code explicitly tolerates) breaks the equality that a "membership" event validated under organization A actually originated from organization A's GitHub install.

### Finding Description
`Shipit::GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for the resolved organization: [1](#0-0) 

The organization used to resolve which `GitHubApp`/secret to check is derived directly from the untrusted JSON body before any verification occurs: [2](#0-1) [3](#0-2) 

That same unverified `params` hash (including `organization.login` and `member.login`) is passed straight to the handler: [4](#0-3) 

`MembershipHandler#process` uses `params.organization.login` to create a `Team` scoped by that organization string and then adds/removes the claimed `member.login` from it, with no re-validation that this organization matches the one whose secret was actually verified: [5](#0-4) 

Team membership is exactly the binding that gates access to the entire engine: `User#authorized?` checks membership against `Shipit.github_teams`: [6](#0-5) 
and `Shipit.github_teams` is derived from configured `oauth.teams` handles resolved via `Team.find_or_create_by_handle`: [7](#0-6) 

The binding that should hold is: `organization used to select/verify the webhook secret == organization asserted inside the payload and used to grant membership`. In a multi-organization deployment (`config/secrets.*.yml` supports keying `github:` by multiple org names, as documented and tested via `secrets_double_github_app.yml`), if any one organization is configured without a `webhook_secret` (which the setup docs mark as *optional*), `verify_webhook_signature` returns `true` for **any** payload claiming to be from that organization, regardless of actual signature. An attacker who can reach the unauthenticated `/webhooks` endpoint can send a `membership` event claiming `organization.login` equal to that unsecured org and `team.id`/`team.slug` equal to a *different, secured* org's privileged team (team IDs/slugs are public GitHub metadata), adding an arbitrary `member.login` (any existing or auto-created Shipit `User`) to that team. Because `Team.find_or_create_by!(github_id: params.team.id)` looks the team up purely by the numeric GitHub team ID supplied in the payload — not scoped to the organization that was actually verified — the attacker effectively grants themselves membership in a team gating `Shipit.github_teams` authorization for a different, secured organization's Shipit instance/repositories.

### Impact Explanation
Successful exploitation grants the attacker's chosen GitHub login membership in a `Shipit.github_teams` team, which is the sole authorization check gating access to Shipit — this leads directly to unauthenticated escalation into `Shipit.github_teams` authorization, one of the explicitly listed High severity impacts (escalation into `Shipit.github_teams` authorization). From there the attacker can log in (via normal OAuth, now passing `current_user.authorized?`) and trigger deploys/rollbacks on the target organization's stacks.

### Likelihood Explanation
This requires a specific configuration precondition (a multi-org Shipit install where at least one configured organization has no `webhook_secret` set) which the documentation explicitly treats as optional/supported (`webhook_secret: some-secret-value` in `docs/setup.md` is described as needed "if you've set a webhook secret during App creation", implying it can be absent), and requires the attacker to know a target team's numeric GitHub `id`/`slug` (obtainable via GitHub's public API for org teams the attacker can see, or via existing team records). No credentials, session, or token are required to reach `/webhooks#create`.

### Recommendation
`MembershipHandler` (and any handler that mutates authorization-relevant state) should re-validate that `params.organization.login` matches the organization actually used to resolve/verify the webhook signature in `WebhooksController`, rather than trusting the same untrusted field twice. Additionally, `webhook_secret` should be mandatory for every configured organization, or `verify_webhook_signature` should fail closed instead of returning `true` when unset.

### Proof of Concept
1. Deploy Shipit configured with two organizations, e.g. `secure-org` (has `webhook_secret`) and `weak-org` (no `webhook_secret` set), as supported by `config/secrets.development.shopify.yml`'s multi-org schema. [8](#0-7) 
2. Attacker (no credentials) sends `POST /webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "organization": { "login": "weak-org" },
  "team": { "id": <secure-org-team-id>, "name": "Admins", "slug": "admins", "url": "https://example.com" },
  "member": { "login": "attacker-github-login" }
}
```
3. `WebhooksController#verify_signature` resolves `repository_owner` → `"weak-org"`, calls `Shipit.github(organization: "weak-org").verify_webhook_signature(...)`, which returns `true` unconditionally because `weak-org` has no `webhook_secret`. [9](#0-8) 
4. `MembershipHandler#process` runs, creates/attaches `Team` with `github_id: <secure-org-team-id>` and adds `attacker-github-login` as a member. [10](#0-9) 
5. Attacker logs in via GitHub OAuth as `attacker-github-login`; `current_user.authorized?` now returns `true` because they belong to the `secure-org` team included in `Shipit.github_teams`.

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
