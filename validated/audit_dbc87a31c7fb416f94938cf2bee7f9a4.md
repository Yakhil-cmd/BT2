### Title
Cross-tenant team membership deletion via unchecked `organization` binding in `MembershipHandler#process` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` resolves the target `Team` solely by the attacker-controlled `params.team.id` (GitHub team id) via `Team.find_or_create_by!(github_id: ...)`, and never verifies that `params.organization.login` — the value used by `WebhooksController#verify_signature` to select which organization's secret authenticated the request — actually matches the `organization` column already stored on that `Team` record. This lets a webhook signed for one Shipit-configured organization delete a `Membership` belonging to a different organization's team.

### Finding Description
The binding that must hold is: `organization_that_signed_request == team.organization` (the org whose `webhook_secret` verified the payload must equal the org that owns the `Team` being mutated).

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and looks up `Shipit.github(organization: repository_owner)` to verify the signature against that specific org's secret [2](#0-1) . Membership payloads carry no `repository` key, so `repository_owner` falls back to `params.organization.login` — a field fully controlled by whoever crafts the JSON body.
- `MembershipHandler#process` then resolves `team = find_or_create_team!` using only `params.team.id` as the lookup key: `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login ... }` [3](#0-2) . The `organization=` assignment inside the block only runs on **creation**; if a `Team` with that `github_id` already exists (as it would for any real, previously-synced team), the existing record is returned unchanged, regardless of what `params.organization.login` says.
- `member = User.find_or_create_by_login!(params.member.login)` resolves/creates a user purely from the attacker-supplied login string [4](#0-3) .
- On `action == 'removed'`, `team.members.delete(member)` deletes the `Membership` row joining that team and that user [5](#0-4) , with no re-check that `team.organization` equals the organization whose secret verified the request.

Exploit flow: attacker possesses (per the stated precondition) a valid `webhook_secret` for some Shipit-configured organization B. They send `POST /webhooks` with header `X-Github-Event: membership`, a signature valid for org B, and a JSON body: `{"action":"removed","organization":{"login":"B"},"team":{"id":<org A's real team github_id>,"name":...,"slug":...,"url":...},"member":{"login":"victim"}}`. `verify_signature` passes because it only checks org B's secret against `organization.login = "B"`. `find_or_create_team!` finds the pre-existing `Team` for org A (matched by `github_id`), ignoring the mismatched `organization.login`. The victim's `Membership` in org A's team is deleted, silently revoking their `Shipit.github_teams` authorization — despite them never having been removed from the real GitHub team.

No existing guard prevents this: `ExplicitParameters` only validates payload shape/types, not cross-field organizational consistency; `Team.find_or_create_by!` does not re-validate `organization` on find; there is no post-lookup assertion like `team.organization == params.organization.login`.

### Impact Explanation
A payload authenticated for organization B mutates authorization state (`Membership`, hence `Shipit.github_teams` eligibility) belonging to organization A. This is a cross-tenant write causing denial of legitimate access — a victim silently loses Shipit permissions granted via team membership without any actual GitHub-side change. This is repeatable against any team whose `github_id` the attacker can guess or discover (team ids are often observable/enumerable), and against any victim login, as long as the attacker has one working org secret. Because it lets one org's authenticated event overwrite another org's authorization records, it matches the "payload for one repository/organization mutating another's ... team" Critical category.

### Likelihood Explanation
The attack requires: (1) the attacker to already possess a valid `webhook_secret` for at least one Shipit-configured organization (the question's stated precondition, not independently established by this trace) and (2) knowledge of the victim's login and the target team's GitHub `github_id`. Given that precondition, no further privilege is needed — the request is a single unauthenticated HTTP POST with a forged JSON body. The `find_or_create_team!` lookup-by-`github_id` behavior and absence of an organization-equality check are the root cause and are unconditionally present in the code, so the divergence is deterministic once the precondition is met.

### Recommendation
After resolving `team` in `find_or_create_team!` (or in `MembershipHandler#process`), enforce `team.organization == params.organization.login` (i.e., the org that was cryptographically verified by `verify_signature`) before performing `add_member`/`team.members.delete`, and raise/drop the event otherwise. Additionally, `WebhooksController#verify_signature` should avoid trusting `params.organization.login` for `repository_owner` resolution when it can diverge from the actual owner of the resource being mutated deeper in the handler.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/membership_handler_test.rb` conceptually — actual file out of scope per rules, described here for reference only):
1. Create `team_a = Team.create!(github_id: 111, organization: 'org-a', name: 'Team A', slug: 'team-a', api_url: '...')`.
2. Create `victim = User.find_or_create_by_login!('victim')` and `Membership.create!(team: team_a, user: victim)`.
3. Build payload: `{"action" => "removed", "organization" => {"login" => "org-b"}, "team" => {"id" => 111, "name" => "Team A", "slug" => "team-a", "url" => "..."}, "member" => {"login" => "victim"}}`.
4. Instantiate `Shipit::Webhooks::Handlers::MembershipHandler.new(payload)` (bypassing `verify_signature`, simulating that org-b's signature already passed) and call `.call`/`.process`.
5. Assert: `Membership.exists?(team: team_a, user: victim)` is still `true` (test should fail on current code because the membership is deleted despite the signed organization, `org-b`, not equaling `team_a.organization`, `org-a`).

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L24-24)
```ruby
          member = User.find_or_create_by_login!(params.member.login)
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L29-30)
```ruby
          when 'removed'
            team.members.delete(member)
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
