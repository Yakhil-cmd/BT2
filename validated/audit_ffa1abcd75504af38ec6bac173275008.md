### Title
Unsigned Solana-style webhook forgery escalates an unauthenticated attacker into `Shipit.github_teams` authorization when `webhook_secret` is not configured - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for the GitHub App matched to the inbound payload's organization/repository owner. Combined with `Webhooks::Handlers::MembershipHandler`, which blindly creates/updates a `Team` and appends any attacker-supplied `member.login` to it, this lets a remote, credential-less attacker forge a `membership` webhook event that adds themselves to any `Team` tracked by Shipit — including ones referenced by `Shipit.github_teams` — thereby satisfying `User#authorized?` and bypassing `force_github_authentication`.

### Finding Description
`WebhooksController#verify_signature` selects which `GitHubApp` config to validate the request against, based purely on the payload's own `repository.owner.login` (or `organization.login` fallback): [1](#0-0) [2](#0-1) 

The actual signature check is performed in `GitHubApp#verify_webhook_signature`: [3](#0-2) 

Note line 77: `return true unless webhook_secret`. Since the setup docs describe `github.webhook_secret` as something you fill in only "if you've set a webhook secret during App creation" (i.e., optional), an operator can legitimately run a Shipit instance — single-org or one of the "Multiple GitHub Applications" orgs shown in the docs — without a configured `webhook_secret`: [4](#0-3) [5](#0-4) 

For any organization whose app config has no `webhook_secret`, the `X-Hub-Signature` header is never actually validated — any POST body claiming that organization is accepted as authentic, with zero credentials required.

The `membership` webhook handler then trusts the payload wholesale: [6](#0-5) 

`find_or_create_team!` locates/creates a `Team` keyed only by the attacker-supplied `team.id`/`team.name`/`team.slug`, and `team.add_member(member)` unconditionally appends the attacker-controlled `member` (resolved via `User.find_or_create_by_login!`, which only needs to resolve a real GitHub login — the attacker's own account works): [7](#0-6) [8](#0-7) 

Team membership is exactly what gates application access: `User#authorized?` checks whether the user belongs to any team in `Shipit.github_teams`, and `force_github_authentication` enforces this on every request: [9](#0-8) [10](#0-9) 

This mirrors the M-28 class of bug: a field that is actually used to select/gate the trust decision (which secret to verify with, here derived from `repository.owner.login`/`organization.login`) is decoupled from the enforcement that should cover the full payload. When the enforcement path degrades to a no-op (`return true unless webhook_secret`), the equality binding "organization that authenticated" == "organization/team acted upon" collapses entirely — the payload is acted upon without ever being covered by a verified signature.

### Impact Explanation
An attacker with no Shipit session, no `ApiClient` token, and no GitHub credentials beyond their own public GitHub account can add themselves to a `Team` referenced by `Shipit.github_teams`, bypassing `force_github_authentication` and gaining full authenticated access to the Shipit UI/API — an authentication/authorization bypass, matching the "escalation into `Shipit.github_teams` authorization" High-impact category. The same missing-secret condition also allows forging `push`, `status`, `pull_request`, and other webhook events for any tracked repository/stack, enabling unauthorized triggering of deploy-adjacent workflows (e.g., `GithubSyncJob`, fake commit statuses).

### Likelihood Explanation
Exploitability is entirely dependent on an operator leaving `webhook_secret` unset for at least one configured GitHub App — a state the code explicitly tolerates (`return true unless webhook_secret`) and the documentation frames as optional rather than mandatory. Where that condition holds, the attack requires only a single unauthenticated HTTP POST with a valid GitHub event header and a real GitHub login for `member.login`.

### Recommendation
- Make `webhook_secret` mandatory: fail closed if unset (raise/deny) instead of returning `true` in `GitHubApp#verify_webhook_signature`.
- Validate that the organization/owner used to select the verification secret is the same organization the resulting handler action modifies, rather than trusting attacker-controlled payload fields for both.

### Proof of Concept
1. Deploy Shipit with a GitHub App config where `webhook_secret` is `nil` (as shown in `test/dummy/config/secrets_double_github_app.yml`).
2. As an unauthenticated attacker, `POST /webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": {"id": <id_of_privileged_team>, "name": "privileged-team", "slug": "privileged-team", "url": "https://api.github.com/teams/1"},
  "organization": {"login": "<org_configured_without_webhook_secret>"},
  "member": {"login": "<attacker_own_github_login>"}
}
```
3. `verify_webhook_signature` returns `true` (no secret configured), `MembershipHandler#process` runs, adds the attacker as a member of the team.
4. Attacker logs in via GitHub OAuth; `User#authorized?` now returns `true` because they belong to a team in `Shipit.github_teams`, bypassing the intended access restriction enforced by `force_github_authentication`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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
