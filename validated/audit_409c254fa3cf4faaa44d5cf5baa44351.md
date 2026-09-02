### Title
Membership webhook's authenticated organization is not bound to the `Team` record it mutates, allowing cross-organization escalation into `Shipit.github_teams` authorization - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
The external report flags Chainlink `latestAnswer()` calls that are trusted without validating they are still tied to fresh, authenticated data. The structural analog in shipit-engine is `MembershipHandler#find_or_create_team!`, which trusts a webhook's `team.id` to select the `Team` row to mutate, but never checks that the `Team` row actually belongs to the organization whose secret authenticated the request.

### Finding Description
Webhook signature verification is scoped per-organization: `WebhooksController#verify_signature` picks the GitHub App/secret to check against based on `repository_owner`, computed from the payload itself (`params.dig('repository','owner','login') || params.dig('organization','login')`), then verifies the whole raw body's HMAC against that org's `webhook_secret`. [1](#0-0) [2](#0-1) 

This proves only "the request was signed by the org named in this payload's `organization`/`repository.owner` field." It says nothing about which `Team` database row that payload is allowed to modify.

`MembershipHandler#find_or_create_team!` then resolves the target `Team` purely by the numeric `github_id` taken from the payload's `team.id`, with no scoping to `params.organization.login`: [3](#0-2) 

Because `find_or_create_by!` only runs its block on creation, if a `Team` row with that `github_id` already exists (e.g., created for a completely different organization via `Team.find_or_create_by_handle`, which *is* correctly scoped by organization+slug), the existing row is returned unchanged and then mutated: [4](#0-3) [5](#0-4) 

The binding that should hold is:
`organization that authenticated the webhook (via its `webhook_secret`) == organization owning the `Team` row being written`

This binding is not enforced. Only `github_id == params.team.id` is checked.

### Impact Explanation
`Team#add_member` / `team.members.delete` directly control `Shipit::Membership` rows, and `Shipit.github_teams` (configured from `oauth.teams`) is the sole authorization gate in `User#authorized?`: [6](#0-5) [7](#0-6) 

In a multi-org Shipit deployment (explicitly documented, each org having its own `webhook_secret`), an attacker who administers *any* configured GitHub organization — even one with no privileged Shipit teams — can sign a `membership` webhook payload with their own org's secret while setting `team.id` to the numeric GitHub team id of a *different*, privileged team (e.g. one listed in `Shipit.github_teams`) that Shipit already tracks. Because the lookup ignores organization, the attacker's chosen `member.login` gets added to that privileged `Team`, flipping `authorized?` to `true` for an arbitrary GitHub login — granting deploy/rollback/lock/merge access without ever being a real member of the target org or team on GitHub. This matches the accepted High-impact category "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Requires the attacker to control (own the `webhook_secret` of) at least one GitHub organization/app configured in Shipit's `secrets.yml` — a realistic scenario for shared multi-tenant Shipit instances serving several orgs, as directly documented in `docs/setup.md`'s "Using Multiple Github Applications" section. GitHub team ids are small sequential integers, discoverable/enumerable, or the attacker can create teams under their own org until an id collision is found, since they fully control their own org's team creation. No privileged Shipit credentials, session, or `ApiClient` token are required — only the ability to POST a correctly-HMAC-signed JSON body to the public webhooks endpoint.

### Recommendation
Scope the `Team` lookup by both `github_id` and the authenticated `organization.login` (or verify `team.organization == params.organization.login` before mutating), mirroring the scoping already used in `Team.find_or_create_by_handle`. Reject/log-and-drop membership events where an existing `Team` record's `organization` does not match the payload's `organization.login`.

### Proof of Concept
1. Shipit is configured with two orgs, each with its own GitHub App/`webhook_secret`: `victim-org` (whose team `victim-org/admins`, `github_id: 555`, is listed in `Shipit.github_teams`) and `attacker-org` (a normal, non-privileged org, controlled by the attacker as an org owner/app installer).
2. Attacker crafts a `membership` webhook body:
```json
{
  "action": "added",
  "team": {"id": 555, "name": "Admins", "slug": "admins", "url": "https://api.github.com/teams/555"},
  "organization": {"login": "attacker-org"},
  "member": {"login": "attacker_github_login"}
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_for_attacker_org, body)` and POSTs to `/github/webhooks` with `X-Github-Event: membership`.
4. `verify_signature` resolves `repository_owner` to `attacker-org` (no `repository` key present) and validates successfully against `attacker-org`'s known secret [8](#0-7) .
5. `MembershipHandler#find_or_create_team!` looks up `Team.find_or_create_by!(github_id: 555)`, finds the pre-existing `victim-org/admins` row (created earlier via `teams:fetch`/`find_or_create_by_handle`), and returns it unchanged [3](#0-2) .
6. `team.add_member(User.find_or_create_by_login!('attacker_github_login'))` runs, inserting a `Membership` linking the attacker-controlled login to `victim-org/admins`.
7. `User#authorized?` now returns `true` for that login [6](#0-5) , granting full Shipit access despite the attacker never being a member of `victim-org` on GitHub.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
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
