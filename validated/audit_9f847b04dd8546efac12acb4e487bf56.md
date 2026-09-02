### Title
Membership webhook signature is verified against `repository.owner.login`/`organization.login`, but team mutation uses a separate, unauthenticated `organization.login` field — allowing cross‑organization escalation into `Shipit.github_teams` authorization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/org webhook secret to check the HMAC signature against using `repository_owner`, computed as `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . The `MembershipHandler`, however, uses a *different* payload path — `params.organization.login` — to decide which `Team` record to create/find and mutate membership on [2](#0-1) . Because signature verification and the org-scoped side effect can be driven by two independently-attacker-controlled JSON fields in the same payload, an operator who legitimately controls the webhook secret for **one** organization onboarded to a shared Shipit instance can forge a `membership` event that is verified against their own org's secret while acting on an arbitrary other organization's `Team`, including one referenced by `Shipit.github_teams` (the authorization gate for the whole app) [3](#0-2) .

### Finding Description
`Shipit.github(organization: repository_owner)` looks up the app config (and hence webhook secret) keyed by whichever organization name is present at `repository.owner.login`, falling back to `organization.login` only if the `repository` key is absent [4](#0-3) . Both `repository` and `organization` are attacker-controlled top-level keys in the raw JSON body — there is no requirement that they refer to the same GitHub org, and no cross-check is performed once verification succeeds. The controller then dispatches the *entire, unfiltered* JSON payload to all handlers registered for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) .

For a `membership` event, `MembershipHandler` reads `params.organization.login` (a field independent of the `repository.owner.login` used for signature routing) to find-or-create the target `Team` (matched by GitHub numeric `team.id`, itself attacker-supplied) and then adds/removes the attacker-supplied `member.login` from that team [6](#0-5) .

This breaks the intended binding: `organization that authenticated the webhook == organization whose team membership is mutated`. Concretely:
- Set `repository.owner.login = "attacker-org"` (an org the attacker legitimately administers and for which they know/control the Shipit-configured `webhook_secret`, per `docs/setup.md`'s per‑org webhook secret setup) [7](#0-6) .
- Set `organization.login = "victim-org"` and `team.id` equal to the real GitHub numeric ID of a team referenced in `Shipit.github_teams` (team IDs/slugs are discoverable via GitHub's public/team APIs).
- Sign the payload with `attacker-org`'s webhook secret. `verify_signature` passes because it only checks the signature against `attacker-org`'s secret, which is legitimately known to the attacker.
- `MembershipHandler#find_or_create_team!` resolves the *existing* victim `Team` row by `github_id` and calls `team.add_member(member)`, inserting an arbitrary GitHub login (e.g. the attacker's own account) into that team [8](#0-7) .
- `User#authorized?` grants Shipit UI access to any user whose `teams` intersect `Shipit.github_teams` [9](#0-8) , so this forged membership silently grants the attacker authorized access to the entire Shipit deployment (all stacks/orgs configured on that instance), not just their own org.

### Impact Explanation
This is an escalation into `Shipit.github_teams` authorization — explicitly listed as a High-impact class. An attacker who only has legitimate administrative control (and hence webhook-secret knowledge) over a single organization onboarded to a multi-org Shipit instance can forge signed events that grant themselves (or any GitHub login) membership in a privileged team belonging to a different organization, bypassing the intended per-organization trust boundary and gaining authenticated access to the whole Shipit application, including stacks/deploys belonging to organizations they do not control.

### Likelihood Explanation
Requires the attacker to be a legitimate onboarding admin of at least one org configured on a shared multi-org Shipit instance (so they know that org's `webhook_secret`) — this is a realistic deployment pattern per `docs/setup.md`, which describes org-scoped `secrets.yml` `github:` entries each with their own `webhook_secret`, and `TOP_LEVEL_GH_KEYS`/`github_app_config` explicitly support multiple organizations per instance [10](#0-9) . The victim team's numeric GitHub `id` is discoverable via GitHub's API without special privilege. No repository write access, Shipit session, or API token is required — only the ability to POST to the public `/webhooks` endpoint with a validly-signed payload for the attacker's own org.

### Recommendation
Bind the signature-verifying organization to the organization that is actually mutated for every handler. Concretely: derive a single canonical "authenticated organization" during signature verification, pass it into `Handler#call`, and have `MembershipHandler` (and any other org-keyed handler) assert `params.organization.login == authenticated_organization` before performing any lookup/mutation, rejecting the event (422) on mismatch. The same audit should be applied to `repository_owner` vs. `repository.full_name` used by `Handler#repository_name` in `PushHandler` and PR handlers, since those also diverge from the field used for signature routing.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.yml`: `attacker-org` (webhook secret known to the attacker who set it up) and `victim-org` (containing a `Team` already synced into `Shipit.github_teams`, with known GitHub team `id`, e.g. `77`).
2. Craft JSON body:
```json
{
  "action": "added",
  "team": { "id": 77, "name": "Deployers", "slug": "deployers", "url": "https://api.github.com/teams/77" },
  "organization": { "login": "victim-org" },
  "member": { "login": "attacker-account" },
  "repository": { "owner": { "login": "attacker-org" } }
}
```
3. Compute `X-Hub-Signature` as `sha1=HMAC_SHA1(attacker-org's webhook_secret, raw_body)`.
4. POST to `/webhooks` with header `X-Github-Event: membership`.
5. `verify_signature` resolves `repository_owner = "attacker-org"`, verifies successfully with attacker's known secret.
6. `MembershipHandler.call` executes with the full payload, finds the existing `victim-org` team by `github_id: 77`, and adds `attacker-account` as a member — granting the attacker Shipit-wide authorization via `Shipit.github_teams`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-43)
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
```

**File:** lib/shipit.rb (L196-200)
```ruby
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

**File:** docs/setup.md (L20-30)
```markdown
## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
