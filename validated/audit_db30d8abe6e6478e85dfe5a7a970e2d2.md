### Title
Cross-tenant team hijack via unscoped `github_id` lookup in `MembershipHandler#find_or_create_team!` - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` resolves a `Team` purely by the attacker-controlled `params.team.id` (mapped to `github_id`), with no requirement that `params.organization.login` matches the `organization` already stored on that team record. Combined with the fact that webhook signature verification in `WebhooksController#verify_signature` selects the verifying secret using an attacker-controlled `organization.login`/`repository.owner.login` field from the very same payload, an attacker who can produce *any* validly-signed webhook (from any org onboarded to the shared Shipit instance) can add arbitrary GitHub users to a team belonging to a completely different organization, including a team listed in `Shipit.github_teams` used for authorization.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't: `team.organization == params.organization.login` for every mutation of an existing `Team` row. In `find_or_create_team!`: [1](#0-0) 

`Team.find_or_create_by!(github_id: params.team.id)` only uses `github_id`, a globally-unique-but-attacker-guessable integer, as the lookup key. The `do |team| ... team.organization = params.organization.login end` block **only executes when a new record is created**, i.e., ActiveRecord's `find_or_create_by!` semantics mean that if a `Team` row with that `github_id` already exists (e.g., seeded by `rake teams:fetch` via `Team.refresh_members!`, or created earlier by a webhook from the legitimate owning org), the existing record is returned unmodified and the organization check never runs: [2](#0-1) 

Back in `process`, the (possibly victim-owned) `team` object then has `team.add_member(member)` called on it using the attacker-supplied `member.login`: [3](#0-2) 

The provenance of the request is established solely by `WebhooksController#verify_signature`, which derives the organization used to select the verification secret from the payload itself, not from any independently trusted source: [4](#0-3) [5](#0-4) 

Because `repository_owner` is read from `params.dig('repository','owner','login') || params.dig('organization','login')` — both fully attacker-controlled JSON fields — an attacker who owns/administers any org onboarded to this (potentially multi-tenant) Shipit instance can craft a `membership` payload where `organization.login` is set to their own org (so the HMAC verifies against their own known secret via `Shipit.github(organization: repository_owner)`), while `team.id` is set to the `github_id` of a **different, victim** org's team row that already exists in the database.

Exploit flow:
1. Attacker controls an org ("attacker-org") legitimately configured in this Shipit instance's multi-org `secrets.github` config, and thus knows/owns its webhook secret.
2. Victim org's team (e.g., `github_id: 42, organization: 'victim'`) already exists, created previously by `rake teams:fetch` (`Team.refresh_members!`) or an earlier legitimate webhook — this requires no interaction from the victim at request time.
3. Attacker POSTs to `/webhooks` a `membership` event, `X-Github-Event: membership`, signed with `attacker-org`'s webhook secret, with body: `{"action":"added","team":{"id":42,...},"organization":{"login":"attacker-org"},"member":{"login":"attacker-controlled-login"}}`.
4. `verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC verifies successfully (attacker knows this secret).
5. `MembershipHandler#find_or_create_team!` finds the **existing** `Team` row (`github_id: 42`, `organization: 'victim'`) — the creation block, which would set `organization`, never runs.
6. `team.add_member(member)` adds the attacker's chosen user to the victim's team.

Existing guards fail to prevent this because: `verify_signature` only proves the request was signed by *some* org's secret known to Shipit — it never proves that org matches the org that owns the target team; and `find_or_create_by!` provides no equivalent of a "verify existing record belongs to the signing organization" check.

### Impact Explanation
If the victim's team is listed in `Shipit.github_teams` (configured via `github.oauth.teams`), the attacker's chosen user immediately passes `User#authorized?`: [6](#0-5) 

This is a full authentication/authorization bypass — an unprivileged party from a foreign, low-trust org gains privileged access (potentially the ability to log in and act as an authorized Shipit user, deploy, or manage stacks) without ever touching the victim org's actual GitHub team membership. This is repeatable against any `Team` row whose `github_id` the attacker can enumerate or guess, and is not limited to a single victim — any tenant on a shared Shipit instance is at risk from any other tenant. This matches "escalation into `Shipit.github_teams` authorization" (High) and arguably rises to Critical since it grants an unauthorized user Shipit-wide access.

### Likelihood Explanation
Preconditions: (1) the Shipit deployment must support multiple GitHub organizations with independently configured webhook secrets (`github_app_config`/`secrets.github` keyed by org) and the attacker must control one such onboarded, lower-privilege org so they legitimately know its webhook secret; (2) the victim's `Team` row must already exist with a discoverable/guessable `github_id` (plausible, since these are sequential/small integers assigned by GitHub and the row may pre-exist via `rake teams:fetch`). Given those preconditions, exploitation cost is a single crafted HTTP POST with a correctly computed HMAC using the attacker's own known secret — trivial and fully repeatable. If a single-org deployment is used, this path narrows to requiring the (single) `webhook_secret`, which the attacker does not have; the finding is strongest and clearly in-scope for multi-org Shipit deployments, which the codebase explicitly supports (`github_app_config`, `github_organizations`).

### Recommendation
In `find_or_create_team!`, do not trust the numeric `github_id` alone as a cross-organization key. Either:
- Scope the lookup by both `github_id` and `organization`: `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and add a uniqueness/consistency check so an existing team's `organization` cannot silently mismatch the payload's `organization.login` (raise/log and reject on mismatch), or
- Explicitly verify `existing_team.organization == params.organization.login` before allowing any membership mutation, rejecting the webhook otherwise.

Additionally, `WebhooksController#verify_signature` should not use payload-derived organization fields as the sole basis for secret selection without also validating that the resulting organization is the one authorized to mutate the specific records referenced in the payload (repository, team, etc.).

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/membership_handler_test.rb` style):
```ruby
test ":membership webhook signed by one org cannot mutate a team belonging to another org" do
  victim_team = Team.create!(github_id: 42, organization: 'victim', slug: 'admins', name: 'Admins', api_url: 'https://api.github.com/teams/42')

  # Simulate a validly signed webhook from a different org ("attacker-org")
  # whose secret the attacker legitimately knows.
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    stub(verify_webhook_signature: true)
  )

  request.headers['X-Github-Event'] = 'membership'
  body = {
    action: 'added',
    team: { id: 42, name: 'Admins', slug: 'admins', url: 'https://api.github.com/teams/42' },
    organization: { login: 'attacker-org' },
    member: { login: 'mallory' }
  }.to_json

  assert_no_difference -> { victim_team.reload.members.count } do
    post :create, body:, as: :json
  end

  refute victim_team.reload.members.exists?(login: 'mallory'),
    "attacker from 'attacker-org' must not be able to add members to a team owned by 'victim'"
end
```
This test asserts the binding `params.organization.login == team.organization` must be enforced before any membership mutation; as currently implemented, `find_or_create_team!` finds the pre-existing `victim` team by `github_id` alone and `team.add_member(member)` succeeds, so the assertion fails against current code, confirming the vulnerability.

### Citations

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

**File:** app/models/shipit/team.rb (L45-51)
```ruby
    def refresh_members!
      github_api = Shipit.github(organization:).api
      github_members = Shipit::OctokitIterator.new(github_api.get(api_url).rels[:members])
      members = github_members.map { |u| User.find_or_create_from_github(u) }
      self.members = members
      save!
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
