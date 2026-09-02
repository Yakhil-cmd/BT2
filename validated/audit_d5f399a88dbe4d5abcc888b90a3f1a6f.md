This confirms the multi-tenant setup is a real supported configuration: `docs/setup.md` documents "Using Multiple Github Applications" where each organization gets its own `webhook_secret` in `secrets.github.<org>`, and `verify_signature` looks up the app via `Shipit.github(organization: repository_owner)` where `repository_owner` is taken straight from the payload's `organization.login` field.### Title
Cross-organization team confusion in `MembershipHandler#process` allows unauthorized `Membership` deletion for a `Shipit.github_teams` team - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#process` resolves the target `Team` solely via `find_or_create_team!`, which matches by `github_id` alone and never checks that the webhook's `organization.login` equals the resolved `Team#organization`. In a multi-tenant Shipit deployment (`docs/setup.md:182-209`, `config/secrets.development.shopify.yml`), where several unrelated GitHub organizations each have their own configured `webhook_secret`, an org that is itself a legitimately configured (but unrelated) tenant can send a validly signed `membership` `removed` event naming a foreign `team.id`/victim `login`, causing the victim's real `Membership` in the other org's authorization team to be deleted.

### Finding Description
The broken binding: `Membership deletion for team T ∈ Shipit.github_teams` should imply `event.organization.login == T.organization`, but the code never enforces this equality.

Code path:
- `WebhooksController#verify_signature` selects the signing key via `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight out of the payload's `organization.login` (fallback path for membership events, no `repository` key): [1](#0-0) [2](#0-1) 
- Because Shipit explicitly supports "Using Multiple Github Applications", each organization has its own independent `webhook_secret` entry under `secrets.github.<org>` [3](#0-2) , and `Shipit.github_app_config` looks the org up by that name alone: [4](#0-3) .
- `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)`, matching purely on the numeric `github_id` and ignoring `params.organization.login` for any pre-existing row: [5](#0-4) .
- For the `'removed'` branch, the resolved `member` (looked up globally by `login` via `User.find_or_create_by_login!`) is deleted from `team.members` with no re-check that `team.organization` matches the event's claimed organization: [6](#0-5) [7](#0-6) .

Exploit flow: an attacker who legitimately administers **their own** GitHub org, which is one of the multiple organizations configured as a tenant of the same Shipit instance (and therefore knows the `webhook_secret` they themselves set up for it), sends a validly HMAC-signed `POST /webhooks` request with `X-Github-Event: membership`, body `{"action":"removed","organization":{"login":"attacker-org"},"team":{"id":<victim_team_github_id>,...},"member":{"login":"<victim_login>"}}`. `verify_signature` passes because the signature matches `attacker-org`'s own secret over these exact bytes. `find_or_create_team!` then finds the pre-existing `Team` row for `victim_team_github_id` (belonging to a completely unrelated org), and `team.members.delete(member)` deletes the victim's real `Membership`.

Existing guards do not stop this: `verify_signature` only proves the request came from *some* organization owning a valid secret in the config — it says nothing about which `team` or `member` the payload's body may reference, since Shipit's team-lookup ignores the organization claim entirely.

### Impact Explanation
This is a write to another tenant's `Team`/`Membership` state that was never authenticated by that tenant's own organization. If the victim team is one referenced in `Shipit.github_teams` (used by `User#authorized?` to gate access to the whole app: [8](#0-7) ), removing the victim's `Membership` deauthorizes a legitimate operator, denying them access/approval rights in Shipit — an authorization-state mutation triggered by a webhook from an unrelated organization. This is repeatable against any `Team#github_id` known to the attacker (team IDs, while globally issued, are often discoverable via the GitHub API or UI) and against any of that team's members by `login`. The blast radius spans all tenants sharing the Shipit instance, since team lookup has no per-tenant isolation.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment where the attacker's own org is a legitimately configured tenant (a documented, supported configuration per `docs/setup.md`), (2) knowledge of the victim's team `github_id` and a victim member's `login` (both are typically observable, e.g. via the GitHub API or web UI, not secret). No Shipit session, API token, or the victim org's/Shipit's central secrets are required — only the attacker's own legitimately-possessed webhook secret for their own tenant org, and crafting a raw signed POST. This is realistic in any Shipit instance serving several independent organizations/customers.

### Recommendation
In `MembershipHandler#process`/`find_or_create_team!`, enforce that the payload's `params.organization.login` matches the resolved `Team#organization` before performing any mutation; reject (or no-op) the event otherwise. Additionally, scope `Team.find_or_create_by!` by `(github_id, organization)` rather than `github_id` alone, since `github_id` alone cannot distinguish tenant boundaries in a multi-org configuration.

### Proof of Concept
minitest plan (in `test/models/shipit/webhooks/handlers/membership_handler_test.rb` or extending `test/controllers/webhooks_controller_test.rb`):
1. Set up two configured organizations, `"target-org"` (owns `Team` fixture with `github_id: 99`, `organization: "target-org"`, with victim `Membership` for user `login: "victim"`) and `"attacker-org"` (its own distinct `webhook_secret`), mirroring `test/dummy/config/secrets_double_github_app.yml`.
2. Assert precondition: `shipit_teams(:target_team).organization == "target-org"` and the victim's `Membership` exists.
3. Build a `membership` `removed` payload with `organization: { login: "attacker-org" }`, `team: { id: 99, ... }`, `member: { login: "victim" }`; sign it with `attacker-org`'s own `webhook_secret`.
4. POST to `/webhooks` with `X-Github-Event: membership` and the computed `X-Hub-Signature`.
5. Assert the response is `:ok` (signature verification for `attacker-org` succeeds).
6. Assert that `Membership.exists?(team: shipit_teams(:target_team), user: shipit_users(:victim))` is now `false` — demonstrating the victim's `Membership` for `target-org`'s team was deleted by a request whose verified `organization.login` (`"attacker-org"`) does not equal `Team#organization` (`"target-org"`), proving the equality binding is violated. A fixed implementation should keep this assertion `true` (membership persists) because the mismatched organization should be rejected.

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

**File:** app/models/shipit/user.rb (L22-28)
```ruby
    def self.find_or_create_by_login!(login)
      find_or_create_by!(login:) do |user|
        # Users are global, any app can be used
        # This will not work for users that only exist in an Enterprise install
        user.github_user = Shipit.github.api.user(login)
      end
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
