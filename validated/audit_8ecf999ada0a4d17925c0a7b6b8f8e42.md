### Title
Cross-organization forgery of GitHub team membership via `membership` webhook - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate a webhook against using `repository_owner`, computed as `payload.dig('repository','owner','login') || payload.dig('organization','login')`. The `MembershipHandler` that actually performs the write (creating/associating a `Team` and adding a `Membership`) uses a *different* field of the same payload, `params.organization.login`, to decide which organization the team belongs to. Because these two fields are independently attacker-controlled inside a single JSON body, an attacker who legitimately administers one GitHub organization configured in Shipit (and therefore knows that organization's `webhook_secret`) can forge a signed `membership` webhook whose `repository.owner.login` points to their own org (satisfying signature verification) while `organization.login` points to a victim organization, causing Shipit to create/modify `Team` and `Membership` records for the victim org.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-30,59-62` resolves the signing secret via:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

`lib/shipit/github_app.rb#verify_webhook_signature` only checks that the raw request body HMACs correctly against the secret configured for the organization selected above — it never checks that the body's *content* is internally consistent (i.e., that `repository.owner.login` and `organization.login`, when both present, refer to the same org): [3](#0-2) 

`MembershipHandler#process` and `#find_or_create_team!`, however, use a *different* payload field — `params.organization.login` — to determine which organization a `Team` belongs to, and adds the specified `member` to that team: [4](#0-3) 

Since Shipit supports multiple GitHub organizations each with their own App/`webhook_secret` (see `config/secrets.development.shopify.yml`), an org that is onboarded to the same Shipit instance can compute a valid HMAC over an arbitrary payload using its own secret. Because `repository_owner` prioritizes `repository.owner.login`, the attacker can include a `repository` object naming their own org (so the correct/known secret is selected for verification) alongside an `organization` object naming the victim org (so the write targets the victim's `Team`). The equality that should hold — "the organization whose secret authenticated the request" == "the organization whose Team/membership state is written" — is broken.

### Impact Explanation
Team membership managed via the `membership` webhook is the same mechanism used by `Shipit::Authentication#force_github_authentication` to gate application access: users must belong to a team in `Shipit.github_teams` to be `authorized?`. [5](#0-4) 

By forging cross-org `membership` events, an attacker who controls one tenant organization's webhook secret can add arbitrary GitHub logins (including their own) as members of a `Team` scoped to a different organization, and that team may be one of the teams listed in `Shipit.github_teams`. This constitutes escalation into `Shipit.github_teams` authorization — explicitly listed as a High-severity impact category — potentially granting the attacker authenticated access to stacks/deploys belonging to an organization they have no legitimate relationship with.

### Likelihood Explanation
Requires only: (1) the attacker administers a GitHub organization that is one of the tenants configured in this Shipit instance (and therefore legitimately knows that org's own webhook secret, which they set when creating their own GitHub App), and (2) the ability to send a raw HTTP POST to the shared `/webhooks` endpoint with a crafted JSON body and a correctly computed `X-Hub-Signature` header. No Shipit session, `ApiClient` token, or victim-org credentials are required, so likelihood is moderate-to-high in any multi-tenant Shipit deployment.

### Recommendation
- In `WebhooksController#verify_signature`, require that `repository.owner.login` (when a `repository` key is present) and `organization.login` (when present) refer to the same organization before proceeding, rejecting mismatched payloads.
- In `MembershipHandler`/`Handler`, derive the organization scope for team creation from the same trust-anchored value used for signature verification (`repository_owner`), not from an independently attacker-suppliable `organization.login` field.
- More generally, ensure every handler resolves its target organization/repository from the exact field that was cryptographically bound during signature verification.

### Proof of Concept
Conceptual request (attacker administers `attacker-org` in this multi-tenant Shipit instance and knows its `webhook_secret`):
```
POST /webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=<HMAC of body using attacker-org's known webhook_secret>

{
  "action": "added",
  "team": { "id": 999, "name": "Victim Admins", "slug": "victim-admins", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "victim-org" },
  "member": { "login": "attacker" },
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
- `repository_owner` resolves to `attacker-org` → signature verifies successfully against the attacker's own known secret.
- `MembershipHandler` reads `params.organization.login == "victim-org"`, creating/looking up a `Team` scoped to `victim-org` and adding `attacker` as a member, per `find_or_create_team!` / `team.add_member(member)`. [6](#0-5)

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
