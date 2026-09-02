### Title
Membership webhook team lookup keyed only by `github_id` allows cross-organization authorization team takeover - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
Shipit supports multi-tenant configuration where several distinct GitHub organizations are each configured with their own GitHub App / `webhook_secret` [1](#0-0) . The `WebhooksController` verifies the HMAC signature of an inbound `membership` webhook using the secret belonging to the organization named in the payload itself [2](#0-1) . Once that per-organization signature check passes, `MembershipHandler#process` looks up (or creates) the `Team` to mutate using only the GitHub-assigned numeric `team.id` from the payload, without ever checking that the returned team actually belongs to the organization that produced the valid signature [3](#0-2) . This breaks the trust binding "organization that authenticated == organization whose data is written."

### Finding Description
`verify_signature` resolves which app config (and therefore which `webhook_secret`) to validate against purely from the payload's own `repository.owner.login` / `organization.login` field: [2](#0-1)  and [4](#0-3) . This means a request signed with organization X's secret is only proof that the sender controls organization X's webhook — it proves nothing about any other organization referenced elsewhere in the same payload.

For the `membership` event, `MembershipHandler#find_or_create_team!` does:
```ruby
Team.find_or_create_by!(github_id: params.team.id) do |team|
  team.github_team = params.team
  team.organization = params.organization.login
end
``` [5](#0-4) 

The `organization:` assignment only executes inside the creation block — i.e., only when no `Team` with that `github_id` already exists. If a `Team` row already exists in Shipit's database with that `github_id` (e.g., a legitimate, already-synced team belonging to a different, victim organization), `find_or_create_by!` simply returns the existing record, and the handler proceeds to call `team.add_member(member)` [6](#0-5)  — mutating the victim organization's team using only the attacker's own, validly-signed organization's webhook.

`Team` membership is exactly what gates application-wide authorization: `User#authorized?` checks whether the current user belongs to any team in `Shipit.github_teams` [7](#0-6) , and `force_github_authentication` enforces this on every request [8](#0-7) .

### Impact Explanation
An attacker who legitimately administers any GitHub organization that is configured as one of the (possibly many) tenants in Shipit's `github:` config can:
1. Learn/guess the numeric GitHub `github_id` of a `Team` that is referenced in `Shipit.github_teams` for a different, victim organization (team ids are GitHub-global sequential integers, and may be exposed through other GitHub API responses/webhooks the attacker can observe).
2. Send a `membership` webhook, signed with their own organization's `webhook_secret` (which they control), with `action: "added"`, `team.id` set to that victim team's `github_id`, and `member.login` set to their own GitHub login.
3. `MembershipHandler` finds the existing victim `Team` by `github_id` and adds the attacker's `User` as a member via `team.add_member(member)`.
4. `User#authorized?` now returns `true` for the attacker because they belong to a team included in `Shipit.github_teams`, granting them full access to Shipit — including triggering deploys, rollbacks, and other privileged actions.

This is an escalation into `Shipit.github_teams` authorization using only an attacker-controlled organization's own valid webhook credentials, matching the impact bar for "High" (escalation into `Shipit.github_teams` authorization).

### Likelihood Explanation
Requires: (a) a multi-tenant Shipit deployment configuring more than one GitHub organization (a documented, supported configuration [9](#0-8) ), and (b) the attacker controlling one of those organizations enough to deliver arbitrary webhook payloads signed with its `webhook_secret` (i.e., ability to configure a webhook on their own org pointing at the Shipit instance, or ability to trigger GitHub's own membership webhook by adding an arbitrary member to a team in their own org — no privileged Shipit credential needed). No Shipit session, `ApiClient` token, or GitHub App private key is required. This is plausible in any Shipit install serving several orgs/tenants.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and the authenticated `organization` (i.e., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and reject/raise if an existing team with that `github_id` belongs to a different organization than the one whose secret validated the request. More generally, `WebhooksController#verify_signature` should ensure that every organization-scoped identifier acted upon later in the handler chain (`team.organization`, `repository.owner`, etc.) is cross-checked against the organization whose secret actually validated the signature, rather than trusting unrelated identifiers taken from the same unauthenticated JSON body.

### Proof of Concept
1. Configure Shipit with two organizations, `victim-org` and `attacker-org`, each with its own `webhook_secret` (standard multi-tenant setup).
2. In Shipit's DB, a `Team` already exists for `victim-org/admins` with `github_id: 999` (synced from a previous legitimate `membership` webhook), and this team's id is listed in `Shipit.github_teams`.
3. Attacker, who administers `attacker-org`, configures a webhook on `attacker-org` pointing at the Shipit `/webhooks` endpoint (or otherwise crafts a request signed with `attacker-org`'s `webhook_secret`).
4. Attacker sends:
```json
{
  "action": "added",
  "team": {"id": 999, "name": "admins", "slug": "admins", "url": "https://api.github.com/teams/999"},
  "organization": {"login": "attacker-org"},
  "member": {"login": "attacker-user"}
}
```
signed with `attacker-org`'s `webhook_secret` via `X-Hub-Signature`.
5. `verify_signature` succeeds (uses `attacker-org`'s secret, matching `organization.login`).
6. `MembershipHandler#find_or_create_team!` finds the existing `Team` with `github_id: 999` (`victim-org/admins`) and calls `team.add_member(attacker_user)`.
7. `attacker-user`, once they log into Shipit via GitHub OAuth, now passes `User#authorized?` because they are a member of a team in `Shipit.github_teams`, gaining full access to `victim-org`'s stacks.

### Citations

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

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
