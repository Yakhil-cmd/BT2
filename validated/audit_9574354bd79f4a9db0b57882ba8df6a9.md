### Title
Webhook signature verification keys off `repository.owner.login`/`organization.login` while event handlers act on a different, attacker-controlled payload field, allowing forged `membership` events to grant Shipit team authorization - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to check the `X-Hub-Signature` against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. The actual event handlers, however, act on independent fields inside the same JSON body (e.g. `MembershipHandler` uses `params.organization.login` and `params.team.id`, while `PushHandler`/base `Handler#repository_name` use `payload.dig('repository', 'full_name')`). Because these are separate, unrelated keys in the same attacker-supplied JSON body, and because `GithubApp#verify_webhook_signature` trivially returns `true` when an organization's `webhook_secret` is unset (`return true unless webhook_secret`), an attacker can pick an org with no configured `webhook_secret` for the field used in verification while pointing the field used by the handler at a completely different, "real" organization/repository/team. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
The webhook signature check and the webhook business logic bind to two different pieces of attacker-controlled data:

1. **Verification binding**: `verify_signature` picks the GitHub App/secret via `repository_owner`, which reads `repository.owner.login` if present, else `organization.login`. [4](#0-3) 
`verify_webhook_signature` short-circuits to `true` when the selected org's `webhook_secret` is blank — a supported/documented configuration (`webhook_secret: # nil`). [2](#0-1) [5](#0-4) 

2. **Execution binding**: `MembershipHandler` (which does not require a `repository` key at all) trusts `params.organization.login` and `params.team.id`/`slug`/`name` to look up or create a `Team`, and adds `params.member.login` (a GitHub login the handler will auto-create as a `Shipit::User`) as a member of that team. [6](#0-5) 
`Team.find_or_create_by!(github_id: params.team.id)` looks up strictly by the attacker-supplied numeric `github_id`; if this matches an already-existing `Team` row (created previously via a legitimate webhook/sync), the handler does not re-validate `organization`/`slug` against it — it just appends the attacker-chosen `member` to that team. [7](#0-6) 

Because `repository_owner` (used to select the signing secret) and `organization.login`/`team.id` (used by the handler to grant membership) come from unrelated JSON keys in the same request body, an attacker can:
- Set `repository.owner.login` to an organization configured in `secrets.github` with no `webhook_secret` (a valid, documented configuration), causing `verify_signature` to pass unconditionally with any/no `X-Hub-Signature` header, since `Shipit.github(organization: repository_owner)` resolves to that no-secret app config. [8](#0-7) 
- Set the top-level `event` header to `membership`, and set `organization.login` / `team.id` / `member.login` to target a *different*, security-relevant organization/team — one whose handle is listed in `Shipit.github_teams` and therefore grants application authorization (`User#authorized?`). [9](#0-8) [10](#0-9) 

Membership team lookups by `github_team.id` (i.e. `Team#github_id`) — while a real GitHub-issued numeric team ID is nominally private, Shipit itself will have already created rows for every team named in `Shipit.github_teams` (fetched from the live GitHub API at boot via `Team.find_or_create_by_handle`), so the `github_id` values for the exact teams that grant authorization already exist as concrete, discoverable database rows the moment the app is configured — the attacker only needs to guess/observe one such ID (e.g., leaked in logs, error messages, or via typical low-cardinality numeric IDs) to target it precisely, without ever needing the corresponding org's `webhook_secret`. [11](#0-10) 

This is the direct analog of the Illuminate `lend()` bug: the fee (signature check) is computed against one field (`lent`, i.e., `repository_owner`/no-secret org), while the actually-consumed/credited value (the premium, i.e., team membership grant) is taken from a different, unchecked field (`organization.login`/`team.id`) of the same transaction.

### Impact Explanation
This breaks the binding "organization that authenticated versus the organization/team that is written." An unauthenticated attacker with no Shipit session, no `webhook_secret`, and no GitHub credentials can forge a `membership` webhook that adds an arbitrary GitHub login (which the handler will auto-provision as a `Shipit::User` via `User.find_or_create_by_login!`) to a `Shipit::Team` whose handle is enumerated in `Shipit.github_teams`. Since `User#authorized?` grants application access purely based on team membership matching `Shipit.github_teams`, this is a direct escalation into Shipit's authorization model — matching the "escalation into `Shipit.github_teams` authorization" High-impact category. It requires only that at least one organization in a multi-org `secrets.github` configuration lacks a `webhook_secret`, which is an explicitly supported and documented setup (`webhook_secret` is optional per `docs/setup.md`).

### Likelihood Explanation
Likelihood depends on:
- A multi-org Shipit deployment (documented, supported feature) where at least one configured organization has no `webhook_secret` set.
- The attacker being able to determine or guess a `github_id` for an existing authorization-relevant `Team` row (created ahead of time by Shipit itself from `Shipit.github_teams`).

Given `webhook_secret` is explicitly optional in the documented configuration schema and multi-org setups are a first-class supported feature, this is a realistic misconfiguration, not a purely theoretical one; and the attack itself needs no credentials, tokens, or sessions — only network access to the public webhook endpoint.

### Recommendation
- Derive the organization used for signature verification from the *same* field the handler will use to make authorization/state-changing decisions (or verify the signature against every configured app's secret, not a payload-selected one).
- For `MembershipHandler` (and any other org/team-mutating handler), cross-check that the verified `X-Github-Event` request's selected `repository_owner`/app-organization matches `params.organization.login` before processing, rejecting mismatches.
- Do not allow `webhook_secret` to be globally optional in multi-org configurations — or at minimum, ensure that a missing secret for org A cannot be used to authenticate payloads that claim to originate from/act on org B.
- In `Team.find_or_create_by!(github_id: ...)`, also validate that `params.organization.login` matches the existing team's `organization` before adding members, rather than trusting `github_id` alone.

### Proof of Concept
Preconditions: Shipit configured with `secrets.github` containing at least two orgs, e.g. `no-secret-org` (no `webhook_secret`) and `victim-org` (properly secured, with team `victim-org/deployers` referenced in `oauth.teams`, hence in `Shipit.github_teams`, with an existing `Team` row `github_id: 555`).

```
POST /github/webhooks
X-Github-Event: membership
(no valid X-Hub-Signature required)

{
  "action": "added",
  "repository": { "owner": { "login": "no-secret-org" } },
  "organization": { "login": "victim-org" },
  "team": { "id": 555, "name": "Deployers", "slug": "deployers", "url": "https://api.github.com/..." },
  "member": { "login": "attacker-github-login" }
}
```

1. `WebhooksController#verify_signature` computes `repository_owner = "no-secret-org"` (from `repository.owner.login`), calls `Shipit.github(organization: "no-secret-org").verify_webhook_signature(...)`, which returns `true` unconditionally because that org has no `webhook_secret`. [12](#0-11) [2](#0-1) 
2. `Shipit::Webhooks.for_event('membership')` dispatches to `MembershipHandler`, which uses `params.organization.login` ("victim-org") and `params.team.id` (555) — fields never checked against the verified `repository_owner`. [13](#0-12) 
3. `Team.find_or_create_by!(github_id: 555)` finds the existing `victim-org/deployers` team row, and `team.add_member(User.find_or_create_by_login!("attacker-github-login"))` grants membership. [7](#0-6) 
4. If the attacker subsequently authenticates to Shipit via the standard OAuth login flow as `attacker-github-login`, `User#authorized?` now returns `true` because the user's `teams` include a `Team` whose `id` is in `Shipit.github_teams.map(&:id)`. [9](#0-8) 

Note: I could not verify from the indexed files the exact production route path for the webhooks controller (routes.rb mounting for `WebhooksController` was not directly visible in the retrieved context) or fully confirm whether any additional middleware constrains inbound webhook requests; a Devin session with full repository access would be needed to confirm the exact route and rule out any additional guard not captured by the index.

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```
