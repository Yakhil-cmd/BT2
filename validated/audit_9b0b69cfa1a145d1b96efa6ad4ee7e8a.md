### Title
Membership webhook lets an attacker-controlled GitHub organization forge team membership for a different organization - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify the request against using `repository_owner`, which falls back to `params.dig('organization', 'login')` only when no `repository` key is present. [1](#0-0)  The `membership` event is processed by `MembershipHandler`, which independently reads `params.organization.login` from the same payload to decide which `Team`/organization the membership change applies to. [2](#0-1)  Because these two reads of the payload are not bound to each other by the signature, an attacker who legitimately controls a GitHub organization/app configured in Shipit (and therefore knows/can produce a valid HMAC for that org) can craft a payload whose `repository.owner.login` points at their own org (to pass signature verification) while `organization.login` names a victim organization, causing Shipit to create/update a `Team` and add themselves as a member for an org they do not control.

### Finding Description
The signature-verification binding is: "the organization whose secret authenticated the request" == "the organization whose data is written by the handler." In `verify_signature`, the org used to fetch the verifying `github_app` is derived from the payload itself:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

This value is looked up via `Shipit.github(organization: repository_owner)`, and the per-organization `webhook_secret` (configured for each GitHub App/org) is used to verify `X-Hub-Signature`. [4](#0-3)  If a `repository` key is present in the payload, its `owner.login` takes priority over the `organization.login` key.

`MembershipHandler`, however, never checks `repository_owner` — it trusts `params.organization.login` directly to decide which `Team.organization` gets the membership change:
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [5](#0-4) 

Because a `membership` webhook payload is just JSON crafted by the sender before signing, nothing prevents an attacker who owns/administers a GitHub organization `orgA` (which they have legitimately connected to this Shipit instance, giving them the ability to produce a validly-signed webhook using `orgA`'s `webhook_secret`) from adding an unrelated `repository: {owner: {login: "orgA"}}` block to a `membership` event payload while setting `organization.login` to a victim org `orgB` and `team`/`member` fields naming a team/user in `orgB`. `verify_signature` will resolve `repository_owner` to `orgA`, verify successfully against `orgA`'s secret, and `MembershipHandler` will then write/modify a `Team` scoped to `orgB`, adding the attacker (or an accomplice user) as a member.

Team membership (`Shipit::Team`, `Membership`) is the basis for `Shipit.github_teams`-based authorization used elsewhere in the engine to grant privileged operations (e.g., stack write/deploy permissions gated on org team membership) — see `app/controllers/concerns/shipit/authentication.rb` and `app/models/shipit/user.rb`, which reference `github_teams`. Forging membership in a victim org's team is therefore a path to escalation into that authorization mechanism.

### Impact Explanation
This is a High-impact issue per the given classification: it is an escalation into `Shipit.github_teams` authorization. An attacker who controls one Shipit-connected GitHub organization can forge signed webhooks that manipulate team membership state for an entirely different organization, potentially granting themselves (or a colluding account) elevated permissions gated on team membership in that other org, without ever needing credentials, GitHub org admin rights, or repository access to the victim organization.

### Likelihood Explanation
Likelihood is medium: it requires the attacker to already have a legitimate, Shipit-connected GitHub organization (or App/webhook_secret) of their own — a low bar since Shipit is often self-serve for connecting orgs/repos — and the ability to send a crafted HTTP POST with a valid HMAC signature for that org to the shared `WebhooksController#create` endpoint. No repository write access, GitHub App private key, or victim-side credentials are needed; only the mismatch between the field used for authentication (`repository.owner.login`) and the field used for the write (`organization.login`) needs to be exploited.

### Recommendation
Bind the field consumed for authorization/authentication to the field(s) actually acted upon. Specifically:
- For the `membership` event, `verify_signature`'s `repository_owner` should be computed the same way the handler resolves the organization it will mutate (i.e., prefer `organization.login` over `repository.owner.login` for events that don't logically carry a `repository`, or reject payloads that contain a `repository` key inconsistent with `organization.login`).
- More generally, `MembershipHandler` (and any other handler that derives an org/repo identity from the payload) should assert that the identity it uses to select which record to mutate matches the identity that `verify_signature` used to select the verifying secret, rather than trusting either value independently.

### Proof of Concept
1. Attacker legitimately connects `orgA` to this Shipit instance, obtaining a valid `webhook_secret` relationship (a `GithubHook`/App install for `orgA`).
2. Attacker crafts a `membership` event payload:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Deployers", "slug": "deployers", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "orgB" },
  "member": { "login": "attacker-controlled-user" },
  "repository": { "owner": { "login": "orgA" } }
}
```
3. Attacker computes `X-Hub-Signature` using `orgA`'s `webhook_secret` over the raw JSON body and POSTs it to `/webhooks` with `X-Github-Event: membership`.
4. `WebhooksController#verify_signature` resolves `repository_owner` to `"orgA"` (because `repository.owner.login` is present) and successfully verifies the signature against `orgA`'s secret. [4](#0-3) 
5. `MembershipHandler#process` runs, resolving the team by `params.organization.login == "orgB"`, and adds `attacker-controlled-user` to a `Team` scoped to `orgB`. [6](#0-5) 
6. If any permission/authorization in the app is gated on membership in an `orgB` team (`Shipit.github_teams`), the attacker's user now benefits from that grant despite never being a real member of `orgB`.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L6-43)
```ruby
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
