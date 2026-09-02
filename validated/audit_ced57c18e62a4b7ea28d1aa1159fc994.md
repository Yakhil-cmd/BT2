### Title
Membership webhook handler trusts an unverified `organization.login` field distinct from the field used for signature verification, allowing cross-organization Team/authorization forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
The analog of the buyout-DoS bug class here is a **verified-identity/acted-upon-identity mismatch**: `WebhooksController` selects which GitHub App's `webhook_secret` to verify a delivery's HMAC signature against using one payload field (`repository.owner.login`, falling back to `organization.login`), while `MembershipHandler` independently trusts a *different, separately-declared* payload field (`organization.login`) to decide which `Team` record to create/mutate and which `User` to add to it. These two fields are never cross-checked against each other.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App config used to validate `X-Hub-Signature` like this: [1](#0-0) [2](#0-1) 

`repository_owner` prefers `repository.owner.login` and only falls back to `organization.login` **if `repository` is absent**. This governs *which org's `webhook_secret` must have produced a valid HMAC*, i.e., which org "authenticated" the request.

`MembershipHandler`, however, declares its own parameter schema and acts strictly on `params.organization.login`, `params.team`, and `params.member.login`, with no reference to whatever `repository` key (if any) was used for signature selection: [3](#0-2) 

Because the controller parses the full raw JSON body with `JSON.parse(request.raw_post)` and hands the whole hash to the handler, an attacker who is a legitimate GitHub-App admin/webhook-secret holder for **Org A** (multi-org Shipit installs support one `webhook_secret` per org, see `config/secrets.development.shopify.yml` / `docs/setup.md`) can craft a body that:
- includes `repository.owner.login = "OrgA"` (purely to make `verify_signature` pick Org A's `webhook_secret`, which the attacker knows and can HMAC-sign the whole body with), and
- also includes `organization.login = "OrgB"`, an arbitrary `team` object (id/slug/name of an OrgB team the attacker wants to join), and `member.login = <attacker-controlled-user>`.

`ExplicitParameters` only validates the keys it declares (`organization`, `team`, `member`) and ignores the extraneous `repository` key, so this payload parses successfully. The signature check passes (since it only ever consulted Org A's secret), and `MembershipHandler#process` then creates/finds `Team` scoped to `organization: "OrgB"` and adds the attacker's chosen member to it: [4](#0-3) 

The equality that should hold but doesn't: `organization that authenticated the delivery (repository.owner.login / the org whose webhook_secret validated the HMAC)` == `organization whose Team/membership is mutated (organization.login in the membership payload)`. The code never enforces this.

### Impact Explanation
`Team` membership is directly wired into the app's authorization gate. `Authentication#force_github_authentication` calls `current_user.authorized?`, which is defined as: [5](#0-4) 

`Shipit.github_teams` is built from the `oauth.teams` config (org/slug handles), and `Team.find_or_create_by_handle` maps `"organization/slug"` to a `Team` row: [6](#0-5) [7](#0-6) 

If any configured authorization team belongs to `OrgB` (a plausible setup on a multi-org Shipit instance protecting access via `oauth.teams`), an admin/webhook-secret holder of the unrelated `OrgA` can forge a `membership` webhook that adds an arbitrary `User` login to that `OrgB` team, granting that user `authorized?` access to the entire Shipit instance — an authorization-escalation into `Shipit.github_teams`, matching the "High" impact bucket in scope (escalation into `Shipit.github_teams` authorization). Depending on stack/repository layout this can cascade to unauthorized deploys.

### Likelihood Explanation
This requires the attacker to already hold a valid `webhook_secret` for *some* org configured on the Shipit instance (i.e., be a legitimate GitHub-App admin of at least one onboarded organization) — a real but bounded pre-condition that is explicitly anticipated by the engine's own multi-org design (`docs/setup.md`'s "Using Multiple Github Applications" section, `test/dummy/config/secrets_double_github_app.yml`). Given that precondition, forging the payload requires no further access: it is a single unauthenticated HTTP POST to `/webhooks` with a self-crafted, self-signed body. The vulnerability is deterministic and requires no timing/race window, unlike the original buyout report.

### Recommendation
- In `WebhooksController#verify_signature`, restrict/validate that any org-identifying fields used by downstream handlers (`organization.login`, `repository.owner.login`) are internally consistent, or better: pass the *verified* organization identity explicitly into each handler and have handlers refuse to act on org-identifying fields that don't match it.
- In `MembershipHandler`, derive the organization strictly from the value that was used to select the verifying `webhook_secret` (i.e., `repository_owner`/the controller's verified org), not from an independently-trusted `organization.login` field in the same unauthenticated JSON body.
- Consider requiring `GithubHook::Organization` records (as already modeled in `test/fixtures/shipit/github_hooks.yml`) to enforce a hard binding between the org that signed a delivery and the org whose `Team`/`Membership` rows may be mutated.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications"), where `oauth.teams` includes an `OrgB` team handle used for the authorization gate.
2. As an attacker who administers the `OrgA` GitHub App (and thus knows `OrgA`'s `webhook_secret`), build a JSON body:
```json
{
  "action": "added",
  "repository": { "owner": { "login": "OrgA" } },
  "organization": { "login": "OrgB" },
  "team": { "id": 999, "name": "OrgB Admins", "slug": "orgb-admins", "url": "https://example.com" },
  "member": { "login": "attacker-controlled-login" }
}
```
3. Compute `X-Hub-Signature` HMAC-SHA1 of the raw body using `OrgA`'s known `webhook_secret`.
4. POST to `/webhooks` with header `X-Github-Event: membership`.
5. `verify_signature` uses `repository.owner.login = "OrgA"` → validates against `OrgA`'s secret → passes.
6. `MembershipHandler#process` creates/finds the `OrgB` "orgb-admins" `Team` and adds `attacker-controlled-login` as a member, per [4](#0-3) , without ever having proven possession of `OrgB`'s `webhook_secret`.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-44)
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
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/models/shipit/team.rb (L17-21)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end
```

**File:** app/models/shipit/team.rb (L37-39)
```ruby
    def handle
      "#{organization}/#{slug}"
    end
```
