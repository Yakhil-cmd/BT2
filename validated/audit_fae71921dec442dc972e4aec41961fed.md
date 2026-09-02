### Title
Team-organization binding not re-verified on membership webhook when team already exists, allowing cross-org escalation into `Shipit.github_teams` - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` locates a `Shipit::Team` solely by `github_id`, and only assigns `team.organization = params.organization.login` inside the `find_or_create_by!` create block. When the row already exists (created earlier from the real org's webhook), that block never runs, so the team's stored `organization` is preserved — but the code never checks that the *current* webhook's asserted organization still matches the team's recorded organization before calling `team.add_member(member)`. Any GitHub org that has installed the Shipit webhook (with its own legitimately-configured secret) can sign a `membership` event with an arbitrary `team.id` value and inject a user into any pre-existing `Shipit::Team` whose `github_id` matches, regardless of which org actually owns that team.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't:

`Team#organization` (as recorded at row creation, e.g. `"shopify"`) **==** `params.organization.login` (the organization asserted by the *current* verified webhook) — this equality is required for `add_member` to be a valid authorization decision, but it is never checked.

Code path:
- `WebhooksController#verify_signature` [1](#0-0)  computes `repository_owner` via `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1)  and verifies the signature using `Shipit.github(organization: repository_owner)`. For a `membership` event there is no `repository` key, so `repository_owner` resolves to `params['organization']['login']` — the attacker's **own** org. Since the attacker administers that org's webhook (and therefore controls/knows its webhook secret in a legitimately-configured multi-tenant Shipit install), the signature check passes; it only proves the request came from *some* org configured in Shipit, not that it's authorized to modify `shipit_teams(:shopify_developers)`.
- `MembershipHandler#process` then calls `find_or_create_team!` [3](#0-2) , which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }`. Because the row for `github_id` already exists (created by the legitimate `shopify` org earlier), the block is skipped, `team.organization` stays `"shopify"`, but the found `team` object is returned unchanged and used directly for `team.add_member(member)`.
- No subsequent code compares `team.organization` to `params.organization.login` before performing the membership mutation.

Attacker's exact request: `POST /webhooks` with header `X-Github-Event: membership`, signed with the attacker's own org's webhook secret, body: `{"action":"added","team":{"id":<github_id of shipit_teams(:shopify_developers)>,"name":"x","slug":"x","url":"x"},"organization":{"login":"attacker-org"},"member":{"login":"attacker"}}`. `drop_unhandled_event`, `verify_signature`, and the `ExplicitParameters` schema all pass because they only validate shape and signature-per-asserted-org, not team ownership. `force_github_authentication`/`User#authorized?`/`require_permission!` are irrelevant here since this is an unauthenticated webhook endpoint by design, gated only by signature verification — which this exploit satisfies legitimately for the attacker's own org.

### Impact Explanation
A successful request creates a `Shipit::Membership` row linking the attacker's GitHub user to a `Shipit::Team` that belongs to a different, victim organization (e.g. `shopify_developers`). If that team is referenced in `Shipit.github_teams` for authorization checks (`User#authorized?` / permission gating on stacks), the attacker gains membership-derived authorization they never legitimately held — escalation into `Shipit.github_teams` authorization, matching the High severity category defined in the rules. The attack is repeatable against any team whose `github_id` the attacker can learn or guess (GitHub team IDs are sequential and often discoverable), and is not limited to one target — any team already present in the `shipit_teams` table is at risk from any org onboarded onto the same Shipit instance.

### Likelihood Explanation
Preconditions: (1) the target team row must already exist (trivially true for any long-lived Shipit deployment with real teams synced), (2) the attacker must control/administer at least one GitHub organization that has a legitimately configured webhook against the same Shipit instance (common in multi-tenant Shipit deployments where any org can self-onboard), and (3) the attacker must know or guess the target team's numeric `github_id`. No Shipit session, API token, or `Shipit.github_teams` membership is required — only the ability to sign a webhook payload with a secret the attacker legitimately possesses for their own org. This is a low-cost, fully repeatable attack once the target `github_id` is known.

### Recommendation
In `MembershipHandler#find_or_create_team!` / `#process`, always re-verify that the team's stored `organization` equals `params.organization.login` before performing `add_member`/`delete`, e.g. raise or drop the event if `team.organization != params.organization.login`, regardless of whether the team was just created or already existed.

### Proof of Concept
```ruby
test ":membership from a different verified org must not add members to another org's team" do
  @request.headers['X-Github-Event'] = 'membership'
  team = shipit_teams(:shopify_developers)
  assert_equal 'shopify', team.organization

  attacker_payload = {
    action: 'added',
    team: { id: team.github_id, name: 'x', slug: 'x', url: 'http://example.com' },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker' }
  }.to_json

  Shipit.github(organization: 'attacker-org').expects(:verify_webhook_signature).returns(true)

  assert_no_difference -> { Shipit::Membership.count } do
    post :create, body: attacker_payload, as: :json
    assert_response :ok
  end

  team.reload
  assert_equal 'shopify', team.organization
  refute team.members.exists?(login: 'attacker')
end
```
This test asserts the equality `team.organization == params.organization.login` is enforced before mutation; currently `Membership.count` increases and `team.members` includes `attacker`, proving the vulnerability.

### Citations

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
