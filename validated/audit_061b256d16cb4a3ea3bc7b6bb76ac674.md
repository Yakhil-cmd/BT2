### Title
Cross-organization webhook signature confusion allows forged `membership` events to grant unauthorized `Shipit.github_teams` access - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
Shipit's multi-organization GitHub App configuration lets each organization have its own `webhook_secret` [1](#0-0) . The webhook signature check selects which organization's secret to verify against using a field (`repository.owner.login`, falling back to `organization.login`) that is *not* the same field the `membership` event handler trusts to decide which organization's `Team` to mutate (`organization.login` only) [2](#0-1) [3](#0-2) . An attacker who legitimately controls one organization onboarded to a shared Shipit instance can forge a `membership` webhook whose signature is verified against their own known secret while the payload's `organization.login` names a victim organization, causing Shipit to add the attacker as a member of the victim's `Team`.

### Finding Description
`WebhooksController#verify_signature` computes the organization used to pick the verification secret as:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

This value is passed to `Shipit.github(organization: repository_owner)`, which looks up per-organization app config (including `webhook_secret`) from `secrets.github` [1](#0-0) . Because `repository.owner.login` takes precedence when present, a payload can carry an arbitrary top-level `repository` object (used only for signature-org selection here) that differs from the `organization` object actually consumed by the event handler.

The `membership` event is dispatched to `MembershipHandler`, which reads `params.organization.login` — not `repository.owner.login` — to find-or-create and mutate a `Team`:
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
```
and adds/removes the specified `member` from that team based on `params.action` [5](#0-4) . Real GitHub `membership` webhooks do not include a `repository` key at all, so an attacker fully controls whether one is present and what it contains, since `verify_signature`'s use of it is a Shipit-specific fallback, not something GitHub enforces.

This breaks the binding: **organization whose webhook secret authenticated the request == organization whose `Team`/membership state is written**. An attacker who is an authorized customer/tenant of org `attacker-org` (and therefore knows or can trigger delivery signed with `attacker-org`'s `webhook_secret`) can craft:
```json
{
  "action": "added",
  "team": {"id": <victim_team_github_id>, "name": "...", "slug": "...", "url": "..."},
  "organization": {"login": "victim-org"},
  "member": {"login": "attacker-github-login"},
  "repository": {"owner": {"login": "attacker-org"}}
}
```
signed with `attacker-org`'s webhook secret. `verify_signature` resolves `repository_owner` to `attacker-org`, verifies successfully, but `MembershipHandler` scopes the write to `victim-org`'s team via `params.organization.login`.

### Impact Explanation
If `victim-org`'s team is one of `Shipit.github_teams` (the set of teams that gate access to the whole Shipit instance, computed via `github.oauth_teams` and used in `User#authorized?`) [6](#0-5) [7](#0-6) , this lets the attacker escalate into that authorization set purely by forging a webhook signed with their own org's secret, matching the "escalation into `Shipit.github_teams` authorization" High-impact category. Once added, `User#authorized?` will return true for the attacker's Shipit `User` record on next login, granting them access to stacks/deploys gated by team-based authentication (`Authentication#force_github_authentication`) [8](#0-7) .

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment where at least two organizations are configured under `secrets.github` with distinct `webhook_secret`s (a documented, supported configuration pattern) [9](#0-8) , and (2) the attacker controls/administers one of those organizations (which is the normal trust level of a "tenant" in such a setup, not a Shipit session or privileged account). Given that, forging the payload is trivial (no GitHub API interaction needed, pure HTTP POST to `/webhooks` with a valid HMAC computed from the attacker's own known secret).

### Recommendation
Make `verify_signature`'s organization resolution and the event handlers' organization/repository resolution consistent and mutually authoritative:
- For events without a `repository` key (e.g. `membership`), `repository_owner` should not silently fall back through an attacker-suppliable path that differs from what the handler actually consumes — derive the verification organization from the same field the handler will use (`organization.login` for `membership`, `repository.full_name`'s owner for repo-scoped events), and reject payloads that mix both fields inconsistently (e.g., presence of `repository` on a `membership` event should be rejected, since GitHub never sends it).
- Alternatively/additionally, after verifying the signature against organization `O`, enforce in `MembershipHandler` (and any other org-scoped handler) that `params.organization.login == O`, raising/dropping the event on mismatch.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` (secret `S_A`, known to the attacker as its administrator) and `victim-org` (secret `S_V`, unknown to attacker), per the multi-org schema in `secrets.yml` [9](#0-8) .
2. `victim-org`'s team `victim-org/some-team` is listed in `Shipit.github_teams` used for instance authorization.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: membership`, `X-Hub-Signature` computed as `sha1=HMAC-SHA1(S_A, body)`, and body:
```json
{
  "action": "added",
  "team": {"id": <victim_team_github_id>, "name": "Some Team", "slug": "some-team", "url": "https://api.github.com/teams/x"},
  "organization": {"login": "victim-org"},
  "member": {"login": "attacker-handle"},
  "repository": {"owner": {"login": "attacker-org"}}
}
```
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, loads `attacker-org`'s app/secret, verifies the HMAC successfully.
5. `MembershipHandler#process` runs with `params.organization.login == "victim-org"`, adding `attacker-handle` to the `victim-org/some-team` `Team` record.
6. On the attacker's next GitHub OAuth login to Shipit, `User#authorized?` returns true because `teams` now includes `victim-org/some-team`, granting them access to the whole instance.

Note: I was not able to execute this against a running instance; the finding is derived from static analysis of the cited controller/handler/config code, which I'm confident supports the field-mismatch as described.

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
