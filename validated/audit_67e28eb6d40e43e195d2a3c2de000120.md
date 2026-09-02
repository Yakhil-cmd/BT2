### Title
Cross-organization `membership` webhook authentication bypass via `repository.owner.login`/`organization.login` field divergence — ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the webhook secret to check using `repository_owner`, which reads `params.dig('repository','owner','login')` first and only falls back to `params.dig('organization','login')` if `repository` is absent. `MembershipHandler`, however, never reads `repository` at all — it uses the independent `params.organization.login` field to create/find the `Team` it mutates. An attacker who controls the entire raw JSON body can supply both keys with different values, causing signature verification to authenticate against one org while the handler writes data attributed to a completely different org. The "shared commit SHA" amplification described in the question does not apply here: `MembershipHandler` never resolves a stack, commit, or SHA — it operates purely on `Team`/`User`/`Membership` rows, so that part of the combined claim is inapplicable, but the underlying binding failure itself is real and independently exploitable.

### Finding Description
The intended (but unenforced) invariant is:
`repository_owner (used to pick the secret in verify_signature) == organization used by MembershipHandler to mutate Team rows`.

Trace:
- `verify_signature` picks the app/secret via `repository_owner`: [1](#0-0) , and `repository_owner` prefers `repository.owner.login` over `organization.login`: [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for the selected org: [3](#0-2) . This is the "no-secret org" the attacker names via `repository.owner.login` — any org configured in Shipit without a `webhook_secret` trivially passes verification for an arbitrary body/signature.
- `MembershipHandler` never looks at `repository` at all; its `ExplicitParameters` schema requires only `action`, `team`, `organization`, `member`, and it uses `params.organization.login` (a field completely independent of `repository_owner`) to find-or-create the `Team`, then adds/removes the `member`: [4](#0-3) .

Exploit request: attacker POSTs to `/webhooks` with header `X-Github-Event: membership` and a body such as:
```json
{
  "action": "added",
  "repository": {"owner": {"login": "attacker-org-with-no-secret"}},
  "organization": {"login": "victim-org"},
  "team": {"id": 123, "name": "Owners", "slug": "owners", "url": "https://api.github.com/teams/123"},
  "member": {"login": "attacker-github-login"}
}
```
`verify_signature` resolves `Shipit.github(organization: "attacker-org-with-no-secret")`, which returns `true` unconditionally because that org has no configured `webhook_secret`. Execution proceeds to `MembershipHandler`, which finds or creates `Team.find_or_create_by!(github_id: 123)` attributed to `organization: "victim-org"` and adds the attacker's `User` (created from `params.member.login`) to that team's `memberships` — a real GitHub team ID for `victim-org` is public/discoverable via the GitHub API, so the attacker can target a specific known team.

Existing guards do not catch this: `verify_signature` only validates the HMAC against the org it itself selected (`repository_owner`), never cross-checks that the same org name is the one used later by the handler business logic; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape, not cross-field consistency; there is no `force_github_authentication`/`require_permission!` check on this unauthenticated endpoint since webhook delivery is meant to be authenticated purely by signature.

### Impact Explanation
If the `Team` targeted (`github_id` matching a team already used in `Shipit.github_teams`) is one of the authorization teams, adding the attacker's `User` to that team's memberships makes `User#authorized?` return `true` for the attacker (`Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?`): [5](#0-4) . This is a cross-tenant write — a webhook authenticated by one (misconfigured, secret-less) org mutates team membership state belonging to a different org — matching the Critical category "a payload for one repository mutating another's ... team" and the High category "escalation into `Shipit.github_teams` authorization." Repeatable for any team ID the attacker can enumerate via the public GitHub API, and for `action: 'removed'` an attacker could also strip legitimate members' authorization.

### Likelihood Explanation
Requires the Shipit deployment to have at least one org configured with `Shipit.github(organization: ...)` but no `webhook_secret` set (a plausible misconfiguration, e.g. a sandbox/staging org entry, or any org onboarded without setting up webhook secrets yet) — otherwise `verify_webhook_signature` correctly rejects forged signatures for every org. Given that precondition, the attack is trivial: a single unauthenticated `POST /webhooks` request with attacker-chosen JSON, no GitHub credentials, no Shipit session, and no knowledge of any real secret.

### Recommendation
Bind webhook authentication and business-logic identity to the exact same field. Concretely: make `repository_owner` (or an equivalent identity accessor) use the identical field the handler consumes (`organization.login` when present, matching what `MembershipHandler` reads), and reject payloads where `repository.owner.login` and `organization.login` are both present but differ. Additionally, treat a missing/blank `webhook_secret` for a configured org as "reject all webhooks" rather than "accept all webhooks," or require an explicit opt-in flag for unsigned orgs.

### Proof of Concept
minitest plan (webhooks controller / membership handler test, no live GitHub):
1. Configure two orgs in test config: `"attacker-org"` with no `webhook_secret`, and `"victim-org"` with a real secret; seed `Shipit::Team.create!(github_id: 123, organization: "victim-org", slug: "owners")` and add it to `Shipit.github_teams`.
2. Assert precondition equality is currently violated: `repository_owner` for the crafted payload resolves to `"attacker-org"`, while `MembershipHandler`'s `params.organization.login` resolves to `"victim-org"` — these must be asserted as unequal before the request.
3. POST to `/webhooks` with header `X-Github-Event: membership`, body as above (repository.owner.login = "attacker-org", organization.login = "victim-org", team.id = 123, member.login = "attacker"), with no valid signature header (or any arbitrary signature).
4. Assert response is `200`/`204` (not `422`), then assert `Shipit::Team.find_by(github_id: 123).members.exists?(login: "attacker")` is `true`, and `Shipit::User.find_by(login: "attacker").authorized?` is `true`.
5. Assert this would not occur if `repository_owner` were bound to the same `organization.login` field the handler uses (regression guard for the fix).

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-43)
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
