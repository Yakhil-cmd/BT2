### Title
Cross-organization team membership mutation via `github_id`-only team lookup in `MembershipHandler#process` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` resolves the `Team` to mutate using `find_or_create_team!`, which looks up an existing `Team` solely by `github_id`, ignoring which organization's webhook actually delivered the payload. Because signature verification in `WebhooksController#verify_signature` authenticates the payload against the organization named by `repository.owner.login` (or `organization.login` as fallback) — a value fully controlled by the attacker inside the JSON body — an attacker who controls any Shipit-integrated GitHub organization (and thus legitimately knows that organization's own `webhook_secret`) can sign a `membership` payload as their own org while setting `team.id` to a victim organization's real `Team#github_id` and `action: 'removed'`, causing `team.members.delete(member)` to strip a legitimate membership belonging to a completely different tenant.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't: `Shipit.github(organization: repository_owner).webhook_secret` (the secret that authenticated this request) `== Shipit::Team#organization` (the tenant whose roster is mutated). The code never establishes or checks this equality.

Path:
1. `WebhooksController#verify_signature` computes `repository_owner` from attacker-controlled JSON: `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and verifies the HMAC signature against `Shipit.github(organization: repository_owner)`'s configured `webhook_secret` [2](#0-1) . This only proves the request was signed by *some* org's secret that the attacker legitimately controls (their own org) — it says nothing about the `team` or `organization` sub-object contents inside the same JSON body.
2. `MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) do |team| team.organization = params.organization.login ... end` [3](#0-2) . The `find_or_create_by!` lookup key is `github_id` alone; if a `Team` row with that `github_id` already exists (e.g. a real team belonging to a victim organization), it is returned unchanged — the block only runs on creation, so `team.organization` is not overwritten, but the *existing victim Team* is the one operated on.
3. Back in `process`, for `action: 'removed'`, `team.members.delete(member)` is executed directly against the victim's `Team` [4](#0-3) , deleting the `Membership` row for the named `member.login`, regardless of the fact that the signing organization (`repository_owner`) is unrelated to the victim team's organization.

Root cause: `Team` lookup by `github_id` has no organization-scoping check against the org whose secret authenticated the request, and `Shipit::Team#add_member`/`members.delete` perform no authorization check of their own [5](#0-4) .

Attacker's exact request: a `POST /webhooks` with header `X-Github-Event: membership`, `X-Hub-Signature` computed with the attacker's own org's `webhook_secret`, and JSON body:
```
{
  "action": "removed",
  "team": { "id": <victim_team_github_id>, "name": "x", "slug": "x", "url": "x" },
  "organization": { "login": "attacker-org" },
  "member": { "login": "<victim_user_login>" },
  "repository": { "owner": { "login": "attacker-org" } }
}
```
`verify_signature` passes because it's checking `attacker-org`'s own secret, which the attacker legitimately possesses as an admin/owner of that org's GitHub integration. `find_or_create_team!` then finds the victim's pre-existing `Team` by `github_id` and the membership row is deleted.

Existing guards do not prevent this: `verify_signature` only proves *a* valid organization signed the request, not that the *named team* belongs to that organization [6](#0-5) ; `drop_unhandled_event` only filters by event type [7](#0-6) ; the `ExplicitParameters` schema in `MembershipHandler` validates types/presence only, not organization ownership of the team [8](#0-7) .

### Impact Explanation
A repository/organization admin who has legitimate access to one Shipit-integrated GitHub org's webhook secret can silently revoke another organization's legitimate user's Shipit team membership by targeting a known/guessable `Team#github_id`. Since `User#authorized?` gates access on `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [9](#0-8) , removing the `Membership` row directly de-authorizes that victim user from deploy/stack access if that was their only qualifying team — a cross-tenant integrity violation matching "a payload for one repository mutating another's ... team," rated Critical per the impact taxonomy. The attack is repeatable against any `Team#github_id` the attacker can enumerate or guess, and works symmetrically for `action: 'added'` (unauthorized privilege grant into `Shipit.github_teams`) as well.

### Likelihood Explanation
Preconditions: the attacker must control (own webhook_secret for) at least one GitHub organization that is configured in Shipit's `secrets.yml`/GitHub Apps config (i.e., a tenant of a multi-tenant Shipit deployment), and must know or guess the victim's `Team#github_id` (GitHub team IDs are sequential/enumerable and often discoverable via the GitHub API for public orgs). No GitHub App private key, `secret_key_base`, or victim's `webhook_secret` is required — only the attacker's own legitimately-held secret. This is realistic for any Shipit instance serving multiple organizations/tenants, a common deployment pattern this engine explicitly supports (`Shipit.github(organization:)` per-org config).

### Recommendation
In `find_or_create_team!`, scope the lookup by both `github_id` and `organization` (matching the authenticated `repository_owner`/`organization.login` from the verified request), or explicitly reject/short-circuit processing when an existing `Team` with the given `github_id` has an `organization` different from the one that signed the webhook. `MembershipHandler#process` should assert `team.organization == params.organization.login` (and that this matches the value used in `verify_signature`) before allowing any `add_member`/`delete` mutation.

### Proof of Concept
minitest plan (extends `test/controllers/webhooks_controller_test.rb` patterns):
```ruby
test ":membership from an unrelated organization's webhook cannot remove another org's team member" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: known
  victim_team.members << shipit_users(:walrus) unless victim_team.members.include?(shipit_users(:walrus))

  @request.headers['X-Github-Event'] = 'membership'
  Shipit.github(organization: 'attacker-org').stubs(:verify_webhook_signature).returns(true)

  payload = {
    action: 'removed',
    team: { id: victim_team.github_id, name: 'x', slug: 'x', url: 'x' },
    organization: { login: 'attacker-org' },
    member: { login: shipit_users(:walrus).login },
    repository: { owner: { login: 'attacker-org' } }
  }

  assert_difference -> { Membership.count }, -1 do
    post :create, body: payload.to_json, as: :json
    assert_response :ok
  end

  # Binding check both sides:
  assert_not_equal 'attacker-org', victim_team.reload.organization
  refute victim_team.members.include?(shipit_users(:walrus))
end
```
This asserts the two sides of the broken binding (signing org `attacker-org` vs. mutated team's `organization` `shopify`) diverge while the `Membership` row is still deleted, with no live GitHub calls (signature stubbed exactly as the existing test suite already does).

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
