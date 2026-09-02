### Title
Membership webhook signature is bound to the sending organization but the `Team` mutation is keyed by attacker-controlled `github_id`, allowing cross-organization escalation into `Shipit.github_teams` authorization - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the webhook secret to validate a payload against using only the organization name extracted from the payload itself (`repository_owner`, falling back to `organization.login`). Once the signature check passes for that organization, `MembershipHandler#process` performs its DB mutation by looking up (or creating) a `Team` keyed on the attacker-controlled `team.id` field from the same payload - with no check that this `team.id`/`github_id` actually belongs to the organization whose secret was used to authenticate the request. This decouples "the organization that authenticated the webhook" from "the `Team` record that gets written," mirroring the reported bug class where the verified/signed portion of the input does not cover the field actually acted upon.

### Finding Description
Signature verification: [1](#0-0) [2](#0-1) 

`repository_owner` is derived purely from `organization.login` when there is no `repository` key (as is the case for `membership` events), and `Shipit.github(organization: repository_owner)` is used only to pick which configured webhook secret to validate the HMAC against.

Mutation performed after signature passes: [3](#0-2) 

`find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id) { ... }` — the block that assigns `team.organization = params.organization.login` only runs on **creation**. If a `Team` row with that `github_id` already exists (e.g., it was created earlier for a different, legitimate organization referenced in `Shipit.github_teams`), the existing record is returned unchanged, and `team.add_member(member)` / `team.members.delete(member)` is executed against it regardless of whether `params.organization.login` matches that team's real organization.

`Shipit.github_teams` gates application authorization: [4](#0-3) [5](#0-4) 

Teams referenced by `Shipit.github_teams` are the DB `Team` rows whose membership directly controls whether `current_user.authorized?` grants access to the whole Shipit application (deploys, rollbacks, stack management).

Multi-organization support is a first-class, documented configuration surface (`Shipit.github(organization:)`, `github_app_config`, `secrets.github` keyed per organization), so an installation can legitimately host several organizations, each with its own GitHub App / webhook secret, while a single set of `Shipit.github_teams` gates access globally.

### Impact Explanation
An attacker who controls (or is an admin of) any organization onboarded to a given Shipit instance - and therefore knows/controls that organization's own GitHub App webhook secret, a normal, unprivileged-relative-to-other-tenants credential - can forge a `membership` webhook:
- signed with their own organization's secret (passes `verify_webhook_signature` because `repository_owner`/`organization.login` matches their org),
- but with `team.id` set to the `github_id` of a `Team` row that is actually one of `Shipit.github_teams` (an authorization-gating team belonging to a completely different, privileged organization),
- and `member.login` set to their own GitHub login.

`MembershipHandler#process` adds their `User` as a member of that authorized `Team`, without ever validating that `params.organization.login` corresponds to the team being mutated. On next login, `current_user.authorized?` returns true for the attacker, granting full access to the Shipit deploy dashboard, task streams, and — critically — the ability to trigger deploys/rollbacks. This matches the "High: escalation into `Shipit.github_teams` authorization" impact class, and can lead to unauthorized deploys/rollbacks (Critical-adjacent impact).

### Likelihood Explanation
Likelihood is moderate-to-high in any Shipit deployment that onboards more than one organization (a supported, documented configuration): the attacker only needs administrative control of their own low-privilege organization's GitHub App (to know its `webhook_secret`, which the setup docs explicitly tell org owners to keep and use) plus the numeric GitHub `team.id` of the target authorized team (discoverable via the public GitHub API for organizations with public team info, or through prior legitimate webhook traffic/logs). No access to the victim organization's webhook secret, GitHub App private key, or a privileged Shipit account is required, satisfying the "unprivileged attacker" requirement.

### Recommendation
In `MembershipHandler`, validate that `params.organization.login` matches the `organization` already stored on the `Team` row being fetched (or re-derive/verify the team's `organization` on every request, not only at creation), and reject the event if there is a mismatch. More generally, `WebhooksController#verify_signature` should ensure the organization used to select the webhook secret is the same organization whose resources (`Team`, `Repository`, `Stack`) the handler subsequently mutates, for every handler, not only rely on payload-shape assumptions.

### Proof of Concept
1. Attacker administers `org-x`, onboarded to the shared Shipit instance with its own GitHub App/webhook secret `secret_x` (`secrets.github[org-x].webhook_secret`).
2. Attacker looks up (via GitHub's public API) the numeric `id` of the real, authorized team referenced in `Shipit.github_teams`, e.g. `org-y/engineering` → `github_id = 999`, which already exists as a `Team` row in Shipit's DB (created when `Shipit.github_teams` was configured/synced).
3. Attacker crafts a `membership` event body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "engineering", "slug": "engineering", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "org-x" },
  "member": { "login": "attacker-github-login" }
}
```
4. Attacker computes `X-Hub-Signature` using `secret_x` (their own known secret) and POSTs to `/webhooks` with `X-Github-Event: membership`.
5. `verify_signature` resolves `Shipit.github(organization: "org-x")` and validates successfully against `secret_x`.
6. `MembershipHandler#process` runs `Team.find_or_create_by!(github_id: 999)`, finds the existing `org-y/engineering` team, creates/finds a `User` for `attacker-github-login`, and calls `team.add_member(member)`.
7. Attacker logs into Shipit via OAuth; `current_user.authorized?` now returns `true` because they are a member of a `Team` in `Shipit.github_teams`, granting unauthorized access to deploy/rollback controls for `org-y`'s stacks.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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
