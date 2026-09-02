[1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Webhook signature verification checks a different organization than `MembershipHandler` acts on, allowing cross-organization team-membership forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` used to validate `X-Hub-Signature` based on `repository.owner.login`, falling back to `organization.login` only when `repository` is absent. `MembershipHandler`, however, always trusts `params.organization.login` (not `repository.owner.login`) to decide which `Team`/organization membership to mutate. These two fields are never cross-checked against each other, so the field that authenticates the request is not the field that is acted upon.

### Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 
and uses that value to pick which org's `webhook_secret` verifies the HMAC signature:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [4](#0-3) 

`MembershipHandler#process`, which actually performs the state change (creating/finding a `Team` and adding/removing a `member`), keys entirely off `params.organization.login`:
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [5](#0-4) 

Real GitHub `membership` webhooks are organization-scoped events and do not include a `repository` key. Because `repository_owner` prioritizes an attacker-suppliable `repository.owner.login` field over `organization.login`, an attacker who legitimately controls a GitHub App installation on their own organization (with a webhook secret they know) can add a spoofed `"repository": {"owner": {"login": "attacker-org"}}` block to a forged `membership` payload while setting `"organization": {"login": "victim-org"}` to any organization already configured in Shipit's `github:` secrets. The controller verifies the HMAC using the attacker's own known `webhook_secret` for `attacker-org` (which they can correctly compute), passing `verify_signature`, while `MembershipHandler` subsequently creates/updates `Team` and `Membership` rows scoped to `victim-org` using the unverified `organization.login` value.

This breaks the binding "an organization that authenticated versus the organization that is written": the org whose secret validated the signature (`attacker-org`) is not the org whose team/membership state is mutated (`victim-org`).

### Impact Explanation
`Team`/`Membership` records back the `Shipit.github_teams` authorization check used by `force_github_authentication` to admit users. By forging `membership` events for a victim organization the attacker controls no secret for, an unprivileged attacker can add arbitrary GitHub logins (including their own) to a `Team` scoped to `victim-org`, or remove legitimate members, without ever needing `victim-org`'s webhook secret. This is a direct escalation into `Shipit.github_teams` authorization, matching the High-severity impact category defined in scope.

### Likelihood Explanation
Exploitation requires only: (1) the attacker have a GitHub App installation on any organization configured in this Shipit instance's `github:` secrets (even a low-privilege one they added themselves, if multi-org config is used) so they know a valid `webhook_secret`, and (2) knowledge of a target team's `github_id`/`slug`/`name` (discoverable via GitHub's public team pages or prior reconnaissance) for the victim org. No Shipit session, API token, or GitHub write access to the victim org is required — only a POST to the public `/webhooks` endpoint with a validly-signed-for-attacker-org payload.

### Recommendation
Do not let `verify_signature` and the event handlers derive "which organization/repository this event belongs to" from different, independently-attacker-controlled fields. Either:
- Verify the signature using the same field the handler will use for authorization (i.e., for `membership` events, always key off `organization.login`, never fall back based on an unrelated `repository` key that shouldn't appear in that event type), or
- After verifying the signature, re-derive and enforce that any `repository.owner.login` / `organization.login` used later by handlers match the organization whose secret validated the request.

### Proof of Concept
1. Attacker creates/owns a GitHub App installation for `attacker-org` in a multi-org Shipit deployment (as documented in `config/secrets.development.shopify.yml`), giving them a valid `webhook_secret` for `attacker-org`.
2. Attacker crafts a JSON body for the `membership` event:
```json
{
  "action": "added",
  "team": {"id": 48, "name": "Ouiche Cooks", "slug": "ouiche-cooks", "url": "https://example.com"},
  "organization": {"login": "victim-org"},
  "member": {"login": "attacker-login"},
  "repository": {"owner": {"login": "attacker-org"}}
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac using attacker-org's webhook_secret>` over the raw body and sends it to `/webhooks` with `X-Github-Event: membership`.
4. `verify_signature` resolves `repository_owner` to `attacker-org` (because `repository.owner.login` is present) and successfully verifies the signature using the attacker's own known secret.
5. `MembershipHandler#process` runs, using `params.organization.login == "victim-org"` to find/create the `Team` and add `attacker-login` as a member of a `victim-org` team, independent of the org that actually authenticated the webhook.

Note: I could not fully confirm within this session how `User#authorized?`/`Shipit.github_teams` consumes `Team`/`Membership` rows (the read of `app/models/shipit/user.rb` did not complete due to tool limits), so the exact authorization gate should be double-checked, but the cross-organization write via `MembershipHandler` against an unverified `organization.login` is confirmed directly in the cited code.

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
