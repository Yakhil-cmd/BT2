### Title
Cross-organization webhook signature scoping combined with `github_id`-only team lookup allows privilege escalation into `Shipit.github_teams` - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`, `app/models/shipit/team.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using `repository_owner`, which for `membership` events falls back to `params.dig('organization','login')`. `MembershipHandler`/`Team.find_or_create_by!` then locate the target `Team` record purely by `params.team.id` (the GitHub numeric team id), never re-checking that the verified organization actually owns that team. If any Shipit-configured GitHub organization has no `webhook_secret` set (a documented, supported configuration state), an attacker can forge a `membership` event that "verifies" against that org while writing to a `Team` record that legitimately belongs to a completely different, monitored organization — inserting themselves as a member of a team used by `Shipit.github_teams` authorization.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:
`verified_organization (repository_owner used in Shipit.github(organization: repository_owner))` **should equal** `team.organization (the org that legitimately owns the Team row being mutated)`.

Trace:
1. `WebhooksController#repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`) computes the verification key as `params.dig('repository','owner','login') || params.dig('organization','login')`. Real GitHub `membership` payloads never include `repository`, so this always resolves to `organization.login` — a field fully controlled by the request body.
2. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) calls `Shipit.github(organization: repository_owner)` and then `github_app.verify_webhook_signature(...)`. In `lib/shipit/github_app.rb:76-83`, `verify_webhook_signature` returns `true` unconditionally `unless webhook_secret` — i.e., for any Shipit-configured organization whose `webhook_secret` is blank/unset (a supported, documented state, see `test/dummy/config/secrets_double_github_app.yml:7,46` and `config/secrets.development.example.yml:11,24,33`), **any** signature (or none at all) passes.
3. Once verification "succeeds" for that attacker-chosen organization, `Shipit::Webhooks.for_event('membership')` dispatches to `MembershipHandler#process` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`).
4. `find_or_create_team!` (`app/models/shipit/webhooks/handlers/membership_handler.rb:38-42`) calls `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }`. Because Rails' `find_or_create_by!` only runs the block on **creation**, if a `Team` row with that `github_id` already exists (created earlier from a legitimate webhook belonging to a different, properly-secured organization), it is returned as-is — its `organization` attribute is never checked against, or overwritten by, the current request's `organization.login`.
5. `team.add_member(member)` (`app/models/shipit/team.rb:41-43`) then inserts `User.find_or_create_by_login!(params.member.login)` — set by the attacker to their own GitHub login — into that pre-existing, real team's `memberships`.
6. If that team is one referenced by `Shipit.github_teams` (`lib/shipit.rb:256-258`), the attacker becomes a member for authorization purposes: `User#authorized?` (`app/models/shipit/user.rb:80-82`) and `Authentication#force_github_authentication` (`app/controllers/concerns/shipit/authentication.rb:20-34`) will now treat the attacker as an authorized Shipit user.

No existing guard closes this gap: `drop_unhandled_event` only checks the event type exists; `ExplicitParameters` schema on `MembershipHandler` requires `organization.login` and `team.id` but never cross-validates them against each other or against a pre-existing `Team#organization`; `verify_signature`'s `GithubOrganizationUnknown` rescue only fires for orgs not configured at all, not for configured-but-secretless orgs.

### Impact Explanation
A single forged, unauthenticated HTTP request to `POST /webhooks` can insert an attacker-controlled GitHub login into a `Shipit::Team` record that backs `Shipit.github_teams` authorization, for an organization the attacker does not own and never authenticated against — matching the "High: escalation into `Shipit.github_teams` authorization" category. The attack is repeatable against any pre-existing team `github_id` known to the attacker (team ids are frequently discoverable via GitHub's public API/UI) as long as at least one Shipit-configured organization has no `webhook_secret`. This crosses tenant boundaries in multi-organization Shipit deployments — a payload nominally "from" org A mutates state belonging to org B.

### Likelihood Explanation
Requires: (1) Shipit configured with the multi-organization `github:` schema (`lib/shipit.rb:170-200`) so `repository_owner`/`organization` actually selects between distinct app configs, and (2) at least one configured organization with `webhook_secret` unset — a real, documented, supported configuration (seen in the example config files). Given that precondition, exploitation costs the attacker nothing beyond crafting one JSON POST with a guessed/known `team.id`; no GitHub credentials, sessions, or API tokens are required, satisfying the "unprivileged internet attacker" threat model.

### Recommendation
- Do not let `verify_signature`'s organization selection be independently attacker-controlled from the field the handler trusts for record identity; require `Team.find_or_create_by!` to also match/validate `organization: params.organization.login` and reject (or reconcile safely) when an existing team's `organization` differs from the verified request's organization.
- Disallow (or explicitly opt-in with a warning) `webhook_secret` being blank per-organization in multi-org configurations; treat a missing secret as verification failure rather than automatic pass.
- Consider deriving `repository_owner` strictly from the same field the corresponding handler will use to scope its writes, rather than an independent fallback.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Stub `Shipit.secrets.github` with two orgs: `RealOrg` (has `webhook_secret: "realsecret"`) and `NoSecretOrg` (no `webhook_secret`), mirroring `test/dummy/config/secrets_double_github_app.yml`.
2. Create `shipit_teams(:real_team)` fixture with `github_id: 999`, `organization: "RealOrg"`.
3. Send `POST /webhooks` with `X-Github-Event: membership`, no `repository` key, body:
```json
{"action":"added","team":{"id":999,"name":"Real Team","slug":"real-team","url":"http://x"},
 "organization":{"login":"NoSecretOrg"},"member":{"login":"attacker"}}
```
and an arbitrary/garbage `X-Hub-Signature` header (or omit it).
4. Assert response is `:ok` (verification passed via `NoSecretOrg`'s absent secret) — proving `Shipit.github(organization: "NoSecretOrg").verify_webhook_signature` returns `true` regardless of signature.
5. Assert `Team.find_by(github_id: 999).organization == "RealOrg"` (unchanged) **and** `Team.find_by(github_id: 999).members.map(&:login).include?("attacker")` — proving the attacker was inserted into `RealOrg`'s team despite the request only ever verifying against `NoSecretOrg`.
6. Optionally stub `Shipit.github_teams` to include this team and assert `User.find_by(login: "attacker").authorized?` is now `true`, demonstrating the authorization escalation end-to-end. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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
