### Title
Cross-organization Team membership mutation via unscoped `github_id` lookup in `MembershipHandler#find_or_create_team!` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` resolves the `Shipit::Team` record to mutate solely by the attacker-supplied numeric `params.team.id`, with no check that the team's `organization` matches the organization whose `webhook_secret` verified the current request. Because `Team.find_or_create_by!` only sets `organization`/`github_team` inside the create block (skipped when a record with that `github_id` already exists), a request signed with one organization's webhook secret can add an arbitrary GitHub user as a member of a `Team` record that belongs to a completely different, previously-onboarded organization.

### Finding Description
The broken binding is: `verifying_org (Shipit.github(organization: repository_owner).webhook_secret)` MUST equal `team.organization (the org that owns the Team row being mutated)`. In code:

- `WebhooksController#verify_signature` computes `repository_owner` from `payload.dig('repository','owner','login') || payload.dig('organization','login')` and verifies the signature against that organization's configured `webhook_secret` [1](#0-0) [2](#0-1) .
- `MembershipHandler#find_or_create_team!` looks the team up purely by `github_id: params.team.id`, and only assigns `organization`/`github_team` attributes inside the `find_or_create_by!` block, which Rails skips entirely if a row with that `github_id` already exists [3](#0-2) .
- `#process` then unconditionally calls `team.add_member(member)` on whatever `Team` row was resolved, without re-checking that `params.organization.login` (the org that signed this request) matches `team.organization` [4](#0-3) .
- `Team#add_member` simply appends the member with no organization assertion [5](#0-4) .

Exploit flow: an attacker owns/controls an organization ("attacker-org") that is already legitimately registered with Shipit (has its own configured `webhook_secret`). A victim organization ("victim-org") already has a `Shipit::Team` row in the DB (created earlier via a legitimate `membership` webhook, or via `Team.find_or_create_by_handle`/rake task) with a known or guessed `github_id` (GitHub team IDs are sequential/enumerable). The attacker sends a `membership` webhook POST, signed with `attacker-org`'s webhook secret, with `organization.login = "attacker-org"` (so `repository_owner` resolves to attacker-org and signature verification succeeds using attacker's own secret) but `team.id = <victim's existing github_id>`, `action = "added"`, and `member.login = <attacker's GitHub username>`. `verify_signature` passes (correct secret for the org named in the payload). `find_or_create_team!` finds the pre-existing victim `Team` row by `github_id` — the create block is skipped, so `team.organization` remains the victim's, untouched by the attacker's `organization.login` field. `process` then calls `team.add_member(attacker_user)`, adding the attacker to a `Team` record that belongs to an org the attacker never controlled or authenticated for.

None of the existing guards catch this: `verify_signature` only proves the request was signed by *some* configured org, not that the org matches the `Team` record being touched; the `ExplicitParameters` schema only validates types/presence, not cross-field/tenant consistency; there is no `require_permission!`/ownership check anywhere in `MembershipHandler`.

### Impact Explanation
This lets a request authenticated for one organization mutate a `Team` record that another organization created/owns — a payload for one org mutating another org's "team" record, which is explicitly a Critical-impact category. The attacker can add themselves (or any GitHub login) to victim-owned `Team.members` for any `github_id` they can enumerate, repeatable against arbitrary teams/orgs configured in the same Shipit instance. Whether this record is subsequently consumed by a `require_permission!`/`deployable?` check depends on how the host application wires `Shipit::Team` into its authorization logic — searching this repository's own code did not turn up a direct `require_permission!`/`deployable?` reference to `Shipit::Team`/`Membership`, so I cannot confirm from this codebase alone that this specific data corruption automatically yields deploy authorization bypass; that link is asserted by the question's stated precondition but not independently verifiable within this engine's indexed code.

### Likelihood Explanation
Preconditions: the attacker needs (a) their own organization already onboarded to the same Shipit instance with a valid `webhook_secret` they legitimately possess (a normal, unprivileged setup step for any org using Shipit), and (b) the ability to guess/enumerate a victim org's existing `Team.github_id` (GitHub team IDs are small sequential integers, easily brute-forced) or otherwise know it. No Shipit session, API token, or victim's secret is required. Given these are low-cost/likely-satisfiable preconditions in any multi-tenant Shipit deployment, likelihood is moderate-to-high.

### Recommendation
In `MembershipHandler#find_or_create_team!`/`#process`, verify that the resolved `Team#organization` equals `params.organization.login` (the organization whose webhook secret verified the request) before performing any mutation; reject/raise if they diverge. Additionally, scope the `find_or_create_by!` lookup by both `github_id` and `organization` (e.g., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`) so a team's `github_id`/`organization` pairing is enforced at read time, not only at creation time.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb
test "membership webhook cannot mutate a team belonging to another organization" do
  victim_team = Shipit::Team.create!(
    github_id: 12345,
    organization: 'victim-org',
    name: 'core',
    slug: 'core',
    api_url: 'https://api.github.com/teams/12345'
  )

  payload = {
    'action' => 'added',
    'team' => { 'id' => 12345, 'name' => 'core', 'slug' => 'core', 'url' => victim_team.api_url },
    'organization' => { 'login' => 'attacker-org' }, # org whose secret actually signed this request
    'member' => { 'login' => 'attacker-user' }
  }

  Shipit::Webhooks::Handlers::MembershipHandler.call(payload)

  victim_team.reload
  assert_equal 'victim-org', victim_team.organization # ownership unchanged
  refute_includes victim_team.members.map(&:login), 'attacker-user',
    "attacker from a different, unrelated organization must not be able to join victim-org's team"
end
```
This test demonstrates that, with the current code, `victim_team.members` **does** end up including `attacker-user` even though the request was verified under `attacker-org`'s secret, proving the org-boundary equality (`verifying_org == team.organization`) is violated.

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
