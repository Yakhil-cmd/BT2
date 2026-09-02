### Title
`MembershipHandler#process` deletes team memberships without verifying the webhook's organization owns the target `Team` - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#process` resolves the `Team` solely by `github_id` and never checks that `params.organization.login` matches the `organization` column already stored on that `Team`. Because GitHub team IDs are global and Shipit's webhook signature verification is scoped per-organization (using whichever organization name appears in the payload), a webhook validly signed for one configured organization can target and delete a `Membership` row that belongs to a team owned by a different organization.

### Finding Description
The broken binding is:
`team.organization == params.organization.login` — this equality is never asserted anywhere in `MembershipHandler#process` or `#find_or_create_team!`.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` from the payload itself: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) . For a `membership` event there is no `repository` key, so `repository_owner` is exactly `params.organization.login` — the value the attacker controls. `verify_signature` then loads `Shipit.github(organization: repository_owner)` and checks the signature against that organization's own configured `webhook_secret` [2](#0-1) . This proves authenticity of "a request from organization X", not "a request authorized to mutate resources belonging to organization Y".
2. `MembershipHandler#process` then does:
```
team = find_or_create_team!
member = User.find_or_create_by_login!(params.member.login)
when 'removed'
  team.members.delete(member)
``` [3](#0-2) 
3. `find_or_create_team!` looks the `Team` up by `github_id` alone; the `organization` assignment only runs inside the `find_or_create_by!` block, which Rails only executes on a fresh insert — not when an existing row is found:
```
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [4](#0-3) 

Consequently, once a `Team` row exists for a given `github_id` (created previously through a legitimate membership webhook from its real owning organization), any other organization configured in the same Shipit instance whose webhook is validly signed can send `action: 'removed'`, `team: { id: <victim_team_github_id> }`, `organization: { login: '<attacker_org>' }`, `member: { login: '<victim_username>' }` and the handler will resolve the pre-existing victim `Team` (ignoring that it belongs to a different org) and call `team.members.delete(member)`, deleting the `Membership` row.

None of the existing guards catch this: `verify_signature`/`GitHubApp#verify_webhook_signature` only prove the payload's claimed organization signed it with its own secret, not that the claimed organization owns the named team [5](#0-4) ; `drop_unhandled_event` and the `ExplicitParameters` schema only enforce shape, not cross-field authorization [6](#0-5) ; there is no model validation tying `Membership`/`Team` lookups to the requesting organization.

### Impact Explanation
A `Membership` row for an arbitrary user in an arbitrary (already-known) `Team` can be deleted by a request authenticated only as a *different* organization onboarded to the same Shipit instance. If that team is used for `Shipit.github_teams`-style authorization (or any Shipit privilege gating tied to team membership), this is a cross-tenant privilege/authorization mutation: an operator's Shipit access tied to team membership can be revoked by an unrelated organization's valid webhook, satisfying "escalation/loss into `Shipit.github_teams` authorization" territory and the "payload for one repository/org mutating another's record" pattern called out in the rules. The blast radius spans any Shipit deployment hosting more than one GitHub organization/team relationship, since `Team.github_id` is global while the authorization check is organization-scoped only for signing.

### Likelihood Explanation
Preconditions: (1) the Shipit instance must be configured for at least two organizations (multi-tenant), (2) the attacker must control (or have webhook-sending capability signed by) one of those configured organizations' `webhook_secret` — this is exactly the threat model referenced by the question ("attacker's org"), (3) the attacker must know the numeric `github_id` of the victim team (GitHub team IDs, not secrets, and may be discoverable/leaked through prior webhook activity or team API access) and the victim member's login (public GitHub username). Given these, the exploit is a single POST to `/webhooks` and is fully repeatable against any team ID the attacker can guess/learn.

### Recommendation
In `MembershipHandler#find_or_create_team!`/`#process`, verify that the resolved `Team#organization` equals `params.organization.login` before performing any mutation; if they differ, raise/reject rather than acting on the team. Additionally, scope the `Team.find_or_create_by!` lookup by `(github_id:, organization:)` rather than `github_id` alone, so a team record can never be matched/mutated by a payload claiming a different organization.

### Proof of Concept
A minitest against `WebhooksController` (or `MembershipHandler` directly) would:
1. Create `shipit_teams(:shopify_developers)` with `organization: 'shopify'`, `github_id: X`, and an existing `Membership` for a real user (e.g., `walrus`).
2. Configure a second organization `attacker-org` in `Shipit.github_teams`/config with its own `webhook_secret`.
3. Send a `membership` webhook signed with `attacker-org`'s secret, headers `X-Github-Event: membership`, body `{ action: 'removed', team: { id: X, ... }, organization: { login: 'attacker-org' }, member: { login: 'walrus' } }`.
4. Assert before: `Team.find_by(github_id: X).organization == 'shopify'` and `Membership.exists?(team_id: X, user: walrus_user) == true`.
5. Assert after posting: `assert_response :ok` and `Membership.exists?(team_id: X, user: walrus_user) == false`, proving the row owned by `shopify` was deleted by a webhook authenticated only as `attacker-org`.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
```ruby
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
