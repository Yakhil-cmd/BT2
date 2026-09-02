## Title
Missing organization-scoping in `MembershipHandler#find_or_create_team!` allows cross-organization team membership escalation - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

## Summary
`MembershipHandler#process` looks up an existing `Team` solely by `github_id`, ignoring the organization that the webhook was verified against, while `WebhooksController#verify_signature` verifies the payload against whatever organization the attacker names in the JSON body (falling back to `organization.login` when no `repository` key is present). An attacker who controls an organization with no configured `webhook_secret` can therefore send an unsigned `membership` webhook naming a victim team's real `github_id` and get themselves added as a member of that team.

## Finding Description
The broken binding: `organization verifying the webhook` (`repository_owner` in `Shipit::WebhooksController#repository_owner`, derived from attacker-controlled `params.dig('organization','login')` when no `repository` key is sent) MUST equal `organization owning the Team row being mutated` (`Team#organization`, set at creation time and never re-checked on update). This binding is broken.

Path: `WebhooksController#create` calls `verify_signature` first [1](#0-0) , which resolves `github_app = Shipit.github(organization: repository_owner)` and `repository_owner` falls back to `organization.login` [2](#0-1) . `verify_webhook_signature` returns `true` unconditionally when the resolved app has no `webhook_secret` configured: `return true unless webhook_secret` [3](#0-2) . So for an attacker-controlled org with no configured secret, verification trivially passes regardless of signature.

`MembershipHandler#process` then runs: `team = find_or_create_team!`, and `find_or_create_team!` executes `Team.find_or_create_by!(github_id: params.team.id) { ... }` [4](#0-3) . Because `github_id` is looked up globally without any organization filter, if a `Team` row already exists with that `github_id` (the victim's real team, previously synced from the victim org), the block is not run (it only runs on creation) — `find_or_create_by!` returns the existing victim `Team` record unmodified, and organization is never re-validated. `process` then does `team.add_member(User.find_or_create_by_login!(params.member.login))` for `action == 'added'` [5](#0-4) , adding the attacker-created `User` to the victim `Team`'s membership.

This defeats the intended trust boundary because the code assumes the only path to mutate a `Team`'s membership is a webhook that was itself verified by the correct owning organization's secret — but the verification step and the mutation step key on different, attacker-influenced values (verification keys on `repository_owner`/`organization.login` from the payload; mutation keys on `team.id` from the payload), and neither is cross-checked against the other.

## Impact Explanation
An unprivileged attacker with no Shipit credentials can add themselves (or any GitHub login) as a member of a real `Shipit::Team` used for `Shipit.github_teams` authorization checks, as long as (a) they control some GitHub organization/login with no `webhook_secret` configured in the host's Shipit config, and (b) they know or can guess/enumerate the victim team's numeric GitHub `github_id`. This is an authorization escalation into `Shipit.github_teams`, matching the High severity category defined in scope ("escalation into `Shipit.github_teams` authorization"). It is repeatable per victim team id and not tied to any particular repository or stack — it affects any team synced into the Shipit `teams` table, which can be used across all stacks/tenants relying on team-based `deployable?`/permission checks.

## Likelihood Explanation
Feasibility depends heavily on host configuration: the attack only works for organizations that Shipit's config resolves to a `GitHubApp` instance with no `webhook_secret` set (`@webhook_secret = @config[:webhook_secret].presence`). Many production Shipit configs may only define app configs for their own known organizations and could raise `GithubOrganizationUnknown` for arbitrary attacker-named orgs, in which case `verify_signature` calls `head(422)` and blocks the request. Whether an attacker-owned org resolves to *some* configured app entry (e.g., a wildcard/default app config with no secret) versus raising `GithubOrganizationUnknown` was not fully confirmed from `lib/shipit.rb` in this session — the `Shipit.github` resolution logic and `GithubOrganizationUnknown` conditions could not be fully traced within the available iterations. If a default/fallback app config without a secret exists, likelihood is high and attacker cost is minimal (a single unauthenticated POST). If no such fallback exists, this path is not reachable for external orgs, reducing likelihood significantly.

## Recommendation
In `find_or_create_team!`, scope the lookup/update by both `github_id` and the verified `organization` (e.g., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)` and raise/reject if an existing team with that `github_id` belongs to a different organization), so a webhook verified for organization A can never mutate a team belonging to organization B. Additionally, consider hardening `WebhooksController#verify_signature`/`GitHubApp#verify_webhook_signature` so that organizations without a configured `webhook_secret` are rejected outright rather than treated as automatically verified, unless that is an intentional opt-out documented for specific deployments.

## Proof of Concept
Minitest plan (no live GitHub):
1. Fixture setup: create `victim_team = Shipit::Team.create!(github_id: 555, organization: 'victim-org', name: 'deployers', ...)` and ensure `Shipit.github_teams` (or equivalent config) references `victim_team` for a `deployable?`/permission check.
2. Configure `Shipit.github` such that organization `attacker-org` resolves to a `GitHubApp` with no `webhook_secret` (or use the existing test double config that has no secret for an unlisted org), while `victim-org` has a real secret.
3. POST to `/webhooks` with header `X-Github-Event: membership` and body:
   `{"action":"added","team":{"id":555,"name":"deployers","slug":"deployers","url":"https://api.github.com/teams/555"},"organization":{"login":"attacker-org"},"member":{"login":"attacker-handle"}}`, with no valid `X-Hub-Signature` (or an arbitrary one).
4. Assert response is `200`/`:ok` (i.e., `verify_signature` did not reject it) — confirming the equality `repository_owner (attacker-org)` was used for verification.
5. Reload `victim_team` and assert `victim_team.members.map(&:login)` now includes `'attacker-handle'`, and assert `Shipit::Team.where(github_id: 555).count == 1` (no new team was created — the existing victim team was mutated) — confirming the equality `Team.organization owning github_id 555` (`'victim-org'`) no longer matches the verifying organization (`'attacker-org'`), demonstrating the broken binding.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-6)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L76-77)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret
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
