### Title
Webhook signature verified against `repository.owner.login`, while `MembershipHandler` mutates a `Team` scoped to the independent `organization.login` field — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate an inbound webhook's HMAC signature against using `repository_owner`, a value taken directly from the untrusted JSON body, preferring `repository.owner.login` over `organization.login` when both are present. `Shipit::Webhooks::Handlers::MembershipHandler`, however, never consults `repository.owner.login` — it always creates/updates a `Team` and its membership using the independent `params.organization.login` field from the same body. Because the signature only proves "this body was signed by whichever org's secret `repository.owner.login` happened to select," it does not prove that `organization.login` (the field actually acted upon) belongs to that same org, breaking the intended binding `signing_org == acted_on_org`.

### Finding Description
In a multi-tenant Shipit deployment (`config/secrets.yml` configures multiple orgs, each with its own `app_id`/`webhook_secret`, as shown in `config/secrets.development.shopify.yml`), the webhook signature check is: [1](#0-0) 

with the org-selection logic: [2](#0-1) 

Note the fallback ordering: `repository.owner.login` is used if present at all, and `organization.login` is only used when `repository` is absent from the payload.

`MembershipHandler`, which handles the `membership` GitHub event, requires and acts on a completely separate `organization` object embedded in the same JSON body, independent of any `repository` key: [3](#0-2) [4](#0-3) 

Because the JSON body is fully attacker-controlled (the caller supplies the raw POST body and computes its own HMAC — `verify_webhook_signature` only checks that the *entire* raw body's HMAC matches the secret picked via `repository_owner`), nothing stops an attacker who legitimately controls one tenant org's webhook secret (e.g., they administer their own GitHub org/App integration wired into this shared Shipit instance) from crafting a `membership` event payload that:
- includes a `"repository": {"owner": {"login": "attacker-org"}}` object so that `verify_signature` selects and successfully validates against **their own** known secret, and
- includes a different `"organization": {"login": "victim-org"}` object, which is the field `MembershipHandler` actually uses to create/update the `Team` record (`team.organization = params.organization.login`) and to add/remove the specified GitHub `member.login` from that team's membership.

This lets an attacker who authenticates as org A's webhook forge team/membership state for org B's `Team`, entirely decoupled from org B's real webhook secret.

### Impact Explanation
`Team` membership backed by GitHub org/team webhooks is the same primitive Shipit uses to drive `Shipit.github_teams`-based authorization (team membership gates which GitHub identities are treated as trusted Shipit users). Forging `added`/`removed` membership events for an arbitrary team (scoped to any `organization.login` string, not tied to the org whose secret validated the request) lets a low-privileged webhook holder for one tenant inject or remove members from a `Team` object that a completely different tenant relies on for authorization decisions — an escalation into `Shipit.github_teams` authorization, which the assessment rules explicitly list as a High-impact outcome.

### Likelihood Explanation
Requires the attacker to hold a legitimate webhook secret for at least one org/tenant configured in the same Shipit instance (a normal, unprivileged position for a tenant in a shared/multi-org Shipit deployment as documented and configured via `config/secrets.yml`). No access to `GITHUB_TOKEN`, `api_clients_secret`, or any other tenant's secret is needed — only knowledge of the attacker's own tenant secret and the ability to craft an arbitrary POST body, both of which are inherent to operating a legitimate webhook integration.

### Recommendation
Bind the signature-verification identity and the identity acted upon to the same field. Concretely, either:
- Verify the signature using the same `organization.login` value that `MembershipHandler` (and any handler lacking a `repository` object) actually consumes, instead of preferring `repository.owner.login`; or
- Have each handler independently re-derive and check that the org/repository it is about to mutate is consistent with the org whose secret validated the signature (i.e., pass the verified `repository_owner`/org identity into the handler and assert equality against `params.organization.login` / `params.repository.full_name` before mutating any `Team`, `Repository`, or `Stack`).

### Proof of Concept
1. Shipit is configured (per `config/secrets.yml`) with two tenants: `attacker-org` (secret known to the attacker, who legitimately manages that org's GitHub App/webhook) and `victim-org`.
2. Attacker crafts a JSON body for event `membership`:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Victim Admins", "slug": "victim-admins", "url": "https://github.com/victim-org/teams/victim-admins" },
  "organization": { "login": "victim-org" },
  "member": { "login": "attacker-controlled-github-user" },
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/irrelevant-repo" }
}
```
3. Attacker signs the raw body with `attacker-org`'s known `webhook_secret` and sends it to `POST /webhooks` with `X-Github-Event: membership` and the resulting `X-Hub-Signature`.
4. `WebhooksController#verify_signature` computes `repository_owner` as `"attacker-org"` (from `repository.owner.login`), calls `Shipit.github(organization: "attacker-org")`, and the signature validates successfully because the attacker signed with the correct (their own) secret.
5. `MembershipHandler#process` runs on the same payload, ignoring `repository` entirely, and creates/updates `Team` with `organization = "victim-org"`, adding `attacker-controlled-github-user` as a member — despite the request never being validated against `victim-org`'s actual webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-21)
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
