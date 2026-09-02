Confirmed: this is exactly the binding described in the rules — "an organization that authenticated versus the repository that is written." The `MembershipHandler` fully trusts `params.organization.login` from the JSON body to create/attribute a `Team` (and thus grant `Shipit.github_teams` membership) even though signature verification is keyed on a *different, independently-controlled* payload field.### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while `MembershipHandler` trusts an unrelated `organization.login` field to attribute team membership - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to verify the HMAC signature with based on a single lookup field, `repository_owner`, but the `membership` event handler that actually mutates authorization state (`Shipit::Team` membership, which feeds `Shipit.github_teams` login gating) reads a payload field that is not cross-checked against the value used for signature selection in any way that pins them to the *same* logical entity within a single delivery. This breaks the intended binding: `organization authenticated == organization written`.

### Finding Description
`WebhooksController#verify_signature` picks the app/secret to verify against like this: [1](#0-0) [2](#0-1) 

`repository_owner` is derived from the raw, attacker-suppliable JSON body itself (`params.dig('repository','owner','login') || params.dig('organization','login')`), not from anything GitHub signs at the transport level beyond the HMAC of the full body. The signature only proves "this body was HMAC-signed with the secret configured for whichever organization `repository_owner` resolves to" — it says nothing about which fields inside that body are trustworthy.

`Shipit::Webhooks::Handlers::MembershipHandler#process` then uses a *different* field, `params.organization.login`, to create/attribute a `Team` and to add/remove a `User` from it: [3](#0-2) 

`Shipit::Team.add_member` / `members.delete` directly mutate `Membership` records, and `Shipit.github_teams` (used by `StacksController` — see `test/controllers/stacks_controller_test.rb:51-60` — to gate all access to Shipit) is derived from `Team.find_or_create_by_handle`, i.e. from these same `Team`/`Membership` rows: [4](#0-3) [5](#0-4) 

The binding that should hold is: *the organization whose secret validated this delivery* == *the organization whose team membership is being mutated*. In the normal GitHub-generated case these are the same value because GitHub always emits `organization.login` for `membership` events and no `repository` object, so `repository_owner` falls back to `organization.login`, and the handler reads the identical key. However, nothing in code enforces that these two payload reads are the same field/value in general — they are two independently-parsed accessors into the same untyped JSON hash, coupled only by convention/shape of genuine GitHub payloads, not by any explicit equality check in `verify_signature` or `MembershipHandler`. If an attacker who knows (or can obtain) the `webhook_secret` for **any** one organization configured in the Shipit instance's `secrets.github` map (e.g., a low-trust/sandbox org that is intentionally registered so that org's members can self-manage `membership` events) can compute a valid `X-Hub-Signature`, they can send an arbitrary raw body of their choosing to `POST /webhooks`. The `repository_owner` accessor (`params.dig('repository','owner','login') || params.dig('organization','login')`) makes it possible to satisfy signature selection using a `repository.owner.login` (or `organization.login`) value that differs from whatever they additionally embed for the handler layer to consume, because JSON allows both `repository` and `organization` top-level objects to appear together with unrelated values, and `MembershipHandler`'s own `params.organization.login` read is completely independent of the `repository_owner` accessor's resolution order and short-circuiting logic.

### Impact Explanation
If exploitable, this crosses the "escalation into `Shipit.github_teams` authorization" boundary explicitly called out as a High-severity impact in scope: an attacker who only knows one organization's webhook secret could add an arbitrary GitHub login (including their own) as a member of a `Team` tied to a *different, victim* organization's `slug`, and if that team's handle is present in `Shipit.github_teams` (the OAuth login gate enforced by `StacksController`), the attacker could gain authenticated access to Shipit for a stack/organization they were never authorized for.

### Likelihood Explanation
This is rated with real uncertainty because full exploitation requires two things this analysis could not conclusively verify from the engine code alone: (1) that an unprivileged attacker can plausibly obtain a valid `webhook_secret` for *any* organization configured in the operator's `secrets.github` map without already having elevated trust (e.g., being a legitimate admin of a smaller/sandbox org that the same Shipit instance also serves), and (2) that `repository_owner`'s dig/fallback behavior can actually be made to diverge from `MembershipHandler`'s `params.organization.login` read in a way GitHub itself would never produce, given `check_if_ping`/`drop_unhandled_event` and `ExplicitParameters` schema validation don't cross-validate these two fields against each other anywhere. Because genuine GitHub `membership` webhooks never include a `repository` key, and the fallback exists specifically to cover that case, the divergent-field attack is only reachable via a forged, non-GitHub-shaped payload — which is exactly the scenario a valid HMAC signature is supposed to rule out, but is not fully ruled out here since the code never re-derives `repository_owner` from the same key that `MembershipHandler` reads after selecting the app.

### Recommendation
In `WebhooksController`, resolve the authorizing organization/repository identity once, and have every handler (in particular `MembershipHandler`) receive and use that same resolved value rather than independently re-reading `organization.login` (or `repository.owner.login`) out of the raw JSON. Concretely: after `verify_signature` succeeds, pass the resolved `repository_owner` into `Shipit::Webhooks.for_event(event)` handlers, and have `MembershipHandler#find_or_create_team!` assert `params.organization.login.casecmp?(resolved_owner)` (raising/aborting on mismatch) before creating or mutating any `Team`/`Membership` record.

### Proof of Concept
Conceptual (not fully verifiable without a live instance/secrets since this depends on an operator's actual `secrets.github` configuration containing multiple organizations):
1. Attacker is a legitimate, low-privilege member of `sandbox-org`, which is configured in this Shipit instance's `secrets.github` with a webhook secret the attacker has learned (e.g., via a receiving endpoint they control on a repo/org they administer, or leaked config).
2. Attacker computes `sha1=HMAC(sandbox_secret, body)` for a hand-crafted `body`:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Admins", "slug": "admins", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "victim-org" },
  "member": { "login": "attacker" },
  "repository": { "owner": { "login": "sandbox-org" } }
}
```
3. `repository_owner` resolves to `sandbox-org` (from `repository.owner.login`), so `verify_signature` validates successfully against `sandbox-org`'s secret.
4. `MembershipHandler#process` reads `params.organization.login` = `"victim-org"`, creating/attributing `Team(organization: "victim-org", slug: "admins")` and adding `attacker` as a member via `Team#add_member`.
5. If `victim-org/admins` is present in `Shipit.github_teams`, the attacker's GitHub login now passes `StacksController`'s "must be a member of `Shipit.github_teams`" check, per the gating logic tested in `test/controllers/stacks_controller_test.rb:51-60`.

This PoC could not be executed against a running instance as part of this analysis; verifying it end-to-end (particularly whether `Team.find_or_create_by_handle` versus `find_or_create_by!(github_id:)` creates a colliding/attacker-controlled record, and whether an operator would ever configure more than one organization) requires a live or test-harness run, which is outside the scope of static code review.

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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
