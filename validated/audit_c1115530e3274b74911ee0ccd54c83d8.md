This confirms the multi-tenant architecture: `Shipit.github(organization:)` supports multiple independently-configured GitHub Apps/orgs, each with its own `webhook_secret`, selected at runtime via `github_app_config(organization)`, keyed off the `organization` value [1](#0-0)  — and `Shipit.github_teams` (the authorization gate for `User#authorized?`) is just a set of `Team` records resolved by handle [2](#0-1) , with no per-organization isolation baked into the `Team` model’s membership-write path.

### Title
Cross-organization Team membership forgery via unscoped `MembershipHandler` lookup enables authorization escalation - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify a webhook's HMAC signature using the `organization` (or `repository.owner.login`) field taken directly from the *unverified* JSON body, then, once verified, hands that same body to event handlers. For the `membership` event, `MembershipHandler#find_or_create_team!` looks up (or creates) a `Team` purely by the GitHub `team.id` in the payload — a value under no cryptographic binding to the `organization.login` that was actually used to select and validate the signing secret — and never re-verifies or updates `team.organization` on an existing record before mutating membership.

### Finding Description
The webhook signature check picks the verification key based on attacker-supplied payload data before the signature is validated: [3](#0-2) 

For a `membership` event there is no `repository` key, so `repository_owner` falls back to `params.dig('organization', 'login')` — again taken from the unverified body — and is used only to pick which org's `webhook_secret` verifies the HMAC over the *whole* raw body [4](#0-3) .

Once verification succeeds (using organization A's own legitimately-known `webhook_secret`, since org A's admins configure their own GitHub App and secret per `secrets.*.yml`), `MembershipHandler#process` runs: [5](#0-4) 

`find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id)`. The `github_id: Integer` and `organization: String` fields both come straight from the JSON payload and are declared merely as `requires`, not cross-checked against each other [6](#0-5) . Crucially, the `organization` attribute is only assigned inside the `find_or_create_by!` block — i.e., only on *creation*. If a `Team` row with that `github_id` already exists (created earlier from a legitimate webhook belonging to a different organization B), the lookup returns the *existing* record without touching `organization`, and the handler proceeds to call `team.add_member(member)` [7](#0-6) , where `member` is resolved via `User.find_or_create_by_login!(params.member.login)` — also fully attacker-controlled.

The binding that should hold is: `organization used to select/verify the webhook_secret == organization owning the Team being mutated`. Before the attack, org A's secret only authorizes writes scoped to org A's own resources. After a forged `membership` webhook with `organization.login = "orgA"` (verified with org A's real secret) but `team.id` equal to a `github_id` already persisted for org B's team, the equality breaks: org A's verified identity is used to add/remove arbitrary GitHub logins to/from org B's `Team`.

### Impact Explanation
`Shipit.github_teams` — which gates `User#authorized?` (the sole authorization check in `Authentication#force_github_authentication`) — is built directly from `Team` records [2](#0-1) [8](#0-7) . If any org B team referenced in `Shipit.github_teams` has a `github_id` an attacker (an administrator of an unrelated, independently-configured org A on the same Shipit instance) can guess or learn, that attacker can add an arbitrary GitHub login (including their own or an accomplice's) into that authorization-granting team — bypassing GitHub's real team membership entirely and escalating into `Shipit.github_teams` authorization. This matches the specified High-severity impact category directly.

### Likelihood Explanation
Requires only that the Shipit deployment host more than one organization (a documented, supported configuration — see `config/secrets.development.shopify.yml` showing two independently keyed orgs) and that the attacker administers a legitimate GitHub App/org on that same instance (hence genuinely possesses their own `webhook_secret`), plus knowledge or a guess of a target `github_id` for a team (numeric GitHub team IDs are not treated as secrets and are exposed via GitHub's own API/UI to broader audiences than org owners). No compromise of the victim org, no Shipit session, and no `ApiClient` token are required — only a crafted, self-signed HTTP POST to the shared webhook endpoint.

### Recommendation
Scope the `Team` lookup/write by the verified organization, not just `github_id`: require `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)` (or explicitly assert equality and raise/reject on mismatch, including on already-existing records) before calling `add_member`/`members.delete`. Additionally, `WebhooksController#verify_signature` should not use attacker-supplied payload fields to select the verification key in a way that a passing signature check from one org's secret is later trusted to authorize writes referencing entities from another org — the handler must independently confirm the target `Team`/`Repository` truly belongs to the organization identified by the verified secret.

### Proof of Concept
1. Attacker is an administrator of GitHub organization `org-a`, which is one of several organizations configured in this shared Shipit deployment (each with its own GitHub App + `webhook_secret`, as in `secrets.*.yml`). Attacker legitimately knows `org-a`'s `webhook_secret`.
2. Attacker learns (via GitHub's public/organization API, or prior legitimate exposure) the numeric `github_id` of a `Team` belonging to victim organization `org-b`, one that is included in `Shipit.github_teams` (i.e., grants access to the Shipit UI).
3. Attacker crafts a `membership` webhook JSON body:
```json
{
  "action": "added",
  "team": { "id": <org-b-team-github-id>, "name": "Whatever", "slug": "whatever", "url": "https://github.com" },
  "organization": { "login": "org-a" },
  "member": { "login": "attacker-github-login" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(org-a-webhook-secret, body)` and POSTs it to the webhooks endpoint with `X-Github-Event: membership`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'org-a')`, whose `webhook_secret` matches, so the signature verifies.
6. `MembershipHandler#find_or_create_team!` finds the pre-existing `Team` row for `org-b` by `github_id` and does not re-check/update `organization`; `team.add_member(User.find_or_create_by_login!('attacker-github-login'))` runs, granting `attacker-github-login` membership in an org-b-owned team.
7. If that team is part of `Shipit.github_teams`, the attacker's GitHub account is now `authorized?` on the Shipit instance without ever being a real member of `org-b`.

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
