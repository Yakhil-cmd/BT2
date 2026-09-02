### Title
Cross-Organization Team-ID Collision in `MembershipHandler` Allows Escalation into `Shipit.github_teams` Authorization - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
The `membership` webhook handler resolves the `Team` record to mutate using only the numeric GitHub `team.id` from the payload, without checking that this team belongs to the same GitHub organization whose webhook secret authenticated the request. This breaks the binding `organization that authenticated == team record that is written`, letting an attacker who legitimately administers *any* GitHub organization configured on the same Shipit instance inject themselves (or anyone) into a `Team` that actually belongs to a *different*, more privileged organization, by forging a `membership` event with a colliding `team.id`.

### Finding Description
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the delivery against purely from an *unverified* field of the JSON body: [1](#0-0) [2](#0-1) 

For `membership` events (no `repository` key), this falls back to `organization.login` in the payload — i.e. the org value is only used to pick which secret verifies the HMAC, and the HMAC is computed over the raw body that *also contains* that same `organization.login` field. So an attacker who legitimately operates their own GitHub organization ("OrgB", with its own valid `webhook_secret` configured in `config/secrets.yml`, per `docs/setup.md`) can produce a validly-signed `membership` payload for OrgB.

The handler that then processes this event resolves the `Team` to write to purely by numeric `github_id`, not by organization: [3](#0-2) 

`Team.find_or_create_by!(github_id: params.team.id)` only uses `github_id` as the lookup key; the `do |team| ... team.organization = ... end` block is executed **only when the record is created**. If a `Team` with that `github_id` already exists — e.g. a privileged team belonging to another configured organization "OrgA" (`Team` model: `belongs_to`-style unique index on `organization`+`slug`, `github_id` stored globally) — the existing record is returned unchanged, and `team.add_member(member)` / `team.members.delete(member)` is executed against it regardless of which organization actually authenticated the request: [4](#0-3) 

Thus the equality that should hold — "the organization whose secret verified this delivery" == "the organization that owns the `Team` being mutated" — is never checked. An attacker who knows (or can discover, e.g. from a public GitHub org/teams page) the numeric `github_id` of a `Team` belonging to OrgA can forge:
```json
{"action":"added","team":{"id":<OrgA_team_github_id>,"name":"x","slug":"x","url":"x"},
 "organization":{"login":"OrgB"},"member":{"login":"attacker"}}
```
signed with OrgB's own `webhook_secret`, which passes `verify_signature` because it is checked against OrgB's secret and OrgB's own login field — both attacker-controlled and self-consistent. The handler then adds `attacker` as a member of OrgA's `Team` record in Shipit's local `Membership` table.

### Impact Explanation
`Shipit.oauth_teams` / `github_teams` gates authentication/authorization to the Shipit instance (per `lib/shipit/github_app.rb`'s `oauth_teams` attribute and `docs/setup.md`'s description of restricting access to teams). Local `Membership` rows created via `Team#add_member` are what Shipit checks for authorization, independent of whether the user is genuinely a GitHub member of that team. By colliding team IDs across organizations configured on the same multi-tenant Shipit instance, an attacker who controls any one configured GitHub organization can grant themselves membership in a `Team` that is used to gate access for a different, more privileged organization — an escalation into `Shipit.github_teams` authorization, matching the report's "High" impact bar.

### Likelihood Explanation
Exploitation requires only: (1) Shipit configured with more than one GitHub organization (a documented, supported configuration in `docs/setup.md`), (2) the attacker legitimately controlling one of those organizations' GitHub App / webhook secret (their own org, not the victim's), and (3) knowledge of the victim `Team`'s numeric GitHub `github_id` (discoverable via GitHub's team API/page for public visibility, or by brute-forcing small integers since collisions are simply on an integer PK). No Shipit session, `ApiClient` token, or the victim organization's `webhook_secret` is required — only crossing an organizational trust boundary that Shipit's own membership-handling code fails to enforce.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` **and** `organization` (matching `params.organization.login`), and reject/recreate if an existing team's `organization` does not match the authenticated organization for this delivery. More generally, `WebhooksController#verify_signature` should bind the verified organization identity to every downstream write path (teams, repositories, stacks) rather than letting handlers re-derive organization/repository identity from unverified payload sub-fields independently.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Note `OrgA`'s privileged `Team` github_id (e.g. `48`, an org restricted via `oauth.teams`).
3. As the legitimate owner/admin of `OrgB`, craft and sign (using OrgB's real `webhook_secret`) a `membership` webhook payload:
```json
{"action":"added","team":{"id":48,"name":"x","slug":"x","url":"http://example.com"},
 "organization":{"login":"OrgB"},"member":{"login":"attacker"}}
```
4. POST it to `/webhooks` with `X-Github-Event: membership` and the valid `X-Hub-Signature` computed with OrgB's secret.
5. `verify_signature` succeeds because it validates against OrgB's own secret/org fields.
6. `MembershipHandler#process` calls `Team.find_or_create_by!(github_id: 48)`, which returns OrgA's existing `Team`, and `team.add_member(attacker_user)` adds `attacker` to it — granting `attacker` Shipit-side membership in OrgA's restricted team, as shown by the resulting row in `memberships` for `team_id` belonging to OrgA and `user_id` for `attacker`. [5](#0-4)

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
