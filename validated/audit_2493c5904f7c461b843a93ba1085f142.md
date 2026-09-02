## Title
`Team` lookup by GitHub team ID is not scoped to the authenticating organization, allowing cross-organization escalation into `Shipit.github_teams` authorization — (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
The `membership` webhook handler resolves the `Team` record to modify using only the numeric GitHub `team.id` from the payload, with no check that this team belongs to the organization whose webhook secret validated the request signature. This mirrors the reported bug class (a value used/acted on without being properly bound/verified against the trusted context) in the deployment-trust sense described by the rules: the organization that authenticated a webhook is not equal to the organization whose `Team`/authorization record actually gets written.

### Finding Description
`WebhooksController#verify_signature` looks up the signing organization from the payload itself and verifies the HMAC using that organization's configured `webhook_secret`: [1](#0-0) [2](#0-1) 

For a `membership` event, `repository_owner` falls back to `organization.login`, i.e. the same field the attacker fully controls in their own, legitimately-configured GitHub organization/App installation.

Once signature verification passes, `MembershipHandler#process` finds-or-creates the `Team` using only the GitHub-assigned numeric `team.id`, and never checks that `params.organization.login` matches the `organization` already stored on that `Team` record: [3](#0-2) 

`Team.find_or_create_by_handle`/`fetch_and_create_from_github`, by contrast, do scope lookups by `organization` and `slug`: [4](#0-3) 
—but the webhook path bypasses this scoped constructor entirely, going straight to `Team.find_or_create_by!(github_id: params.team.id)`.

`User#authorized?`, which gates all UI access, only checks DB-level `Team` membership against `Shipit.github_teams` (config-defined authorized teams), with no re-validation against the organization that produced the membership event: [5](#0-4) 

**The trust binding broken (as an equality):**
`organization that authenticated the webhook (via its own webhook_secret)` ≠ `organization owning the Team record whose membership is mutated`, because the only key used to locate/create the `Team` (`github_id`) is a GitHub-global identifier not scoped to the authenticating organization.

### Impact Explanation
If a Shipit deployment is configured to serve multiple GitHub organizations (the engine explicitly supports this via the multi-org `github:` config block documented in `docs/setup.md`), an attacker who legitimately controls their own GitHub organization (with a GitHub App they own, and thus its own valid `webhook_secret`) can send a correctly-signed `membership` webhook from their own org. If they can guess or otherwise learn the target `Team`'s GitHub numeric team ID (team IDs are sequential/enumerable integers, often discoverable), `find_or_create_by!(github_id: ...)` will match the existing `Team` row belonging to the *victim* organization and add an attacker-chosen member (the attacker's own GitHub login) to it — with `action: 'added'`. If that `Team` is one of the entries in `Shipit.github_teams`, this directly grants the attacker's GitHub identity `authorized?` access to the victim's Shipit instance (stack views, deploy triggers, task logs), i.e. escalation into `Shipit.github_teams` authorization — one of the explicitly in-scope High-impact outcomes.

### Likelihood Explanation
This requires: (1) the Shipit instance to be configured with more than one GitHub organization/App (a documented, supported configuration), (2) the attacker to control a GitHub App/org of their own that is registered in that same Shipit instance, and (3) knowledge of the numeric `github_id` of the target `Team`. All three reduce likelihood compared to a fully unauthenticated exploit, but none require a Shipit session, API token, or any of the explicitly excluded privileges (no `ApiClient` token, no `webhook_secret` of the victim org, no repository access) — only ownership of an unrelated, attacker-controlled GitHub organization onboarded to the same multi-tenant Shipit instance.

### Recommendation
Scope the `Team` lookup in `MembershipHandler#find_or_create_team!` by both `github_id` **and** `organization: params.organization.login` (mirroring `Team.find_or_create_by_handle`), and reject/ignore membership events whose `organization.login` does not match the `organization` already recorded on the existing `Team` row with that `github_id`.

### Proof of Concept
1. Configure Shipit for two organizations, `shopify` (victim, `Shopify/developers` is in `Shipit.github_teams`) and `evil-corp` (attacker-owned, its own valid GitHub App + `webhook_secret`).
2. Attacker discovers/guesses the numeric GitHub team ID of `Shopify/developers` (e.g. via public API enumeration or prior observation).
3. Attacker sends a `membership` webhook, correctly signed with `evil-corp`'s own `webhook_secret`:
```json
{
  "action": "added",
  "team": { "id": <shopify_developers_github_id>, "name": "Developers", "slug": "developers", "url": "https://api.github.com/..." },
  "organization": { "login": "evil-corp" },
  "member": { "login": "attacker-handle" }
}
```
4. `WebhooksController#verify_signature` validates this against `evil-corp`'s secret and passes.
5. `MembershipHandler#find_or_create_team!` calls `Team.find_or_create_by!(github_id: <shopify_developers_github_id>)`, matches the existing `Shopify/developers` `Team` row, and `team.add_member(User.find_or_create_by_login!('attacker-handle'))` adds the attacker's GitHub identity to that team.
6. Attacker signs in via GitHub OAuth as `attacker-handle`; `current_user.authorized?` now returns `true` because they belong to a `Team` present in `Shipit.github_teams`.

**Note:** I was unable to fully confirm from the indexed code how `Shipit.github_teams` resolves configured team handles to `Team` records (the `lib/shipit.rb` contents were not returned by the tools in this session), so the exact mechanics of the final authorization match should be verified directly in that file before treating this as fully confirmed.

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
