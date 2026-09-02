### Title
Cross-organization team hijack via global `github_id` lookup in `MembershipHandler#find_or_create_team!` bypasses `Shipit.github_teams` authorization - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
In multi-organization Shipit deployments, `MembershipHandler#find_or_create_team!` resolves a `Team` purely by the numeric GitHub `github_id`, with no check that the webhook's claimed `organization.login` matches the team's actual owning organization. Because webhook signature verification (`WebhooksController#verify_signature`) is scoped per-organization while `Team` lookup is global, an attacker who legitimately administers *any* other GitHub organization configured in the same Shipit instance can forge a `membership` webhook that adds themselves to a `Team` belonging to a different, privileged organization, escalating into `Shipit.github_teams` authorization.

### Finding Description
The broken binding is: `Team.github_id == params.team.id` should imply `Team.organization == params.organization.login` (the org that actually owns/signed for that GitHub team), but the code never enforces this equality after the record already exists.

- `WebhooksController#verify_signature` verifies the HMAC signature using `Shipit.github(organization: repository_owner)`, where `repository_owner` for a `membership` event falls back to `params.dig('organization', 'login')` [1](#0-0) . In a multi-org config (`docs/setup.md` "Using Multiple Github Applications", exercised by `test/dummy/config/secrets_double_github_app.yml`), each organization has its own `webhook_secret`, so a webhook claiming `organization.login: "OrgB"` is verified strictly against OrgB's secret [2](#0-1) . Since the attacker genuinely administers OrgB, they can produce a valid signature for OrgB.
- `Shipit.github_teams`, which gates authorization (`User#authorized?`), is derived only from the *default* (first-configured) organization's app: `github.oauth_teams` on `Shipit.github` (no `organization:` argument) [3](#0-2) [4](#0-3) . These teams are pre-created `Team` rows tied to the privileged organization (e.g. "OrgA").
- `MembershipHandler#find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login; ... }` [5](#0-4) . Because `find_or_create_by!` matches on `github_id` alone, if a `Team` row with that `github_id` already exists (as it will for any team in `Shipit.github_teams`), the block — which sets `organization` — is skipped entirely, and the existing OrgA-owned `Team` object is returned regardless of the webhook's actual `organization.login`.
- `process` then does `team.add_member(User.find_or_create_by_login!(params.member.login))` [6](#0-5) , creating a `Membership` row linking the attacker-controlled login to OrgA's privileged team.
- `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) , which now returns true for the attacker, and `force_github_authentication` grants full access [8](#0-7) .

GitHub team IDs (`github_id`) are numeric and enumerable via the public GitHub API (`GET /orgs/{org}/teams`) without any Shipit credential, so the attacker can learn OrgA's team `github_id` values in advance. None of the existing guards catch this: `verify_signature` only proves the request came from *an* organization configured in Shipit (OrgB), not from the organization that owns the referenced team; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape, not cross-organization consistency; there is no `require_permission!` or `subset` validator applied to `Team#organization` on the find path.

### Impact Explanation
An attacker who is a legitimate admin of any secondary organization onboarded onto the same multi-tenant Shipit instance can, with a single forged POST to `/webhooks`, silently grant themselves membership in a `Team` gating `Shipit.github_teams`-based authorization for a completely different (higher-privilege) organization. This is a full authentication/authorization bypass: it escalates the attacker into every capability gated by `Shipit.github_teams` (deploy, rollback, merge across all stacks the privileged org's teams can access), matching the Critical "escalation into `Shipit.github_teams` authorization" / "unauthorized deploy, rollback or merge" category. The attack is repeatable for any known `github_id` of a gating team and is not limited to the attacker's own repositories/stacks — it crosses tenant boundaries within the same Shipit deployment.

### Likelihood Explanation
Requires: (1) Shipit configured for multiple GitHub organizations (a documented, supported feature), (2) the attacker legitimately administers one of the other configured organizations (so they can generate a correctly-signed webhook with their own `webhook_secret`), and (3) the target `Team`'s `github_id` (public, enumerable via GitHub API) is already present in the `teams` table (guaranteed for anything in `Shipit.github_teams`, since they're pre-fetched by `Shipit.github_teams`/`teams:fetch`). Given these fairly common multi-tenant deployment conditions, the attack cost is a single crafted HTTP POST with no Shipit credentials needed beyond control of a legitimately configured secondary org, and it is fully repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup/creation by both `github_id` and `organization` (e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and reject/log the event (rather than silently reusing a mismatched team) when a `github_id` collision occurs against a different `organization`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`, using multi-org secrets similar to `test/dummy/config/secrets_double_github_app.yml`):
1. Configure two orgs, `OrgA` (privileged, has `Shipit.github_teams` include a team with `github_id: 999`, `organization: "OrgA"`) and `OrgB` (attacker-administered).
2. Create fixture: `admin_team = Team.create!(github_id: 999, organization: "OrgA", name: "Admins", slug: "admins", api_url: "...")`.
3. Stub/allow `Shipit.github(organization: "OrgB").verify_webhook_signature` to return true (simulating a correctly-signed OrgB webhook, as in existing tests that stub `GithubHook.any_instance.stubs(:verify_signature)`).
4. POST a `membership` webhook: `{ action: 'added', team: { id: 999, name: 'Admins', slug: 'admins', url: '...' }, organization: { login: 'OrgB' }, member: { login: 'attacker' } }`.
5. Assert: **before** — `admin_team.organization == "OrgA"` and no `Membership` exists for `attacker`/`admin_team`. **after** — `assert admin_team.reload.members.exists?(login: 'attacker')` while `admin_team.organization` is still `"OrgA"`, proving a `Membership` for an OrgA-owned privileged team was created off an OrgB-signed webhook (i.e. `Team.find(by: github_id).organization != params.organization.login` yet the membership was still written).
6. Additionally assert `User.find_by(login: 'attacker').authorized?` becomes `true` if that team is included in `Shipit.github_teams`, demonstrating the authorization bypass end-to-end.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** lib/shipit.rb (L170-188)
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
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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
