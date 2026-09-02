### Title
Cross-organization confused deputy in `membership` webhook: `repository_owner` used for signature verification diverges from `params.organization.login` used for the `Team`/`Membership` write - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to check against using `repository_owner`, computed from `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . `MembershipHandler`, however, writes to the `Team` and `Membership` tables using `params.organization.login` and `params.team.id` independently of `repository_owner` [2](#0-1) . Because the attacker fully controls the JSON body, they can set a fake `repository.owner.login` pointing at an organization configured with no `webhook_secret` (which trivially passes verification: `verify_webhook_signature` returns `true` "unless webhook_secret") while setting `organization.login`/`team.id` to a different, real target organization/team whose secret they do not know.

### Finding Description
The broken binding is: **the organization used to select the `GitHubApp`/secret in `verify_signature` (`repository_owner`) must equal the organization whose `Team`/`Membership` rows are mutated by `MembershipHandler` (`params.organization.login`)**. These are read from two different, attacker-controlled JSON paths, so they are not actually bound together.

- `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)` [3](#0-2) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that organization, and otherwise only accepts the legacy `sha1=` algorithm/signature: `return true unless webhook_secret; algorithm, signature = signature.split("=", 2); return false unless algorithm == 'sha1'` [4](#0-3) .
- `MembershipHandler#process`/`#find_or_create_team!` finds or creates the `Team` keyed by `params.team.id` and sets `team.organization = params.organization.login`, then adds/removes `params.member.login` from the team's memberships [5](#0-4) .

Because `Shipit.github(organization:)` in multi-org mode raises `GithubOrganizationUnknown` for organizations not present in `secrets.github` [6](#0-5) , the attacker's fake `repository.owner.login` must name an organization that is actually configured in `secrets.github` but that has no `webhook_secret` set (an explicitly optional field per the docs: "If you've set a webhook secret during the App creation, you should copy it here"). Given such a configured-but-secret-less organization "A" and any real target organization "B" (with a real Shipit team/webhook_secret), the attacker's request:

```
POST /webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=anything   # or omitted
{
  "action": "removed",
  "repository": {"owner": {"login": "A"}},   # only consulted by verify_signature
  "organization": {"login": "B"},            # consulted by the handler for team.organization
  "team": {"id": <B's real GitHub team id>, "name": "...", "slug": "...", "url": "..."},
  "member": {"login": "some-B-member"}
}
```

passes `verify_signature` because `Shipit.github(organization: "A")` has no `webhook_secret`, then `MembershipHandler` finds B's already-synced `Team` (by `github_id`) and removes `some-B-member` from it, or (if the team is new) creates it under `organization: "B"` — all without any credential belonging to organization B. `User#authorized?` computes membership from exactly these `teams`/`memberships` rows: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) , so this write directly controls a real user's authorization status in Shipit.

None of the existing guards prevent this: `drop_unhandled_event` only filters unregistered event types, not organization consistency; `ExplicitParameters` in `MembershipHandler.params` only validates types/shape, not that `organization.login` matches whatever org verified the signature; and `verify_signature` never re-checks the divergence between `repository_owner` and `params.organization.login`.

### Impact Explanation
An attacker who knows (a) any Shipit-configured GitHub organization slug that has no `webhook_secret` set, and (b) the numeric GitHub team ID and member login of a target organization's Shipit-synced team, can add or remove arbitrary users from that target team's `Membership` rows without holding any secret for the target organization. Since `User#authorized?` reads exactly these rows to gate access when `Shipit.github_teams` is non-empty, this is a direct authorization-bypass/escalation vector into `Shipit.github_teams`, matching the High severity category ("escalation into `Shipit.github_teams` authorization"). It is repeatable per request and only bounded by knowledge of team IDs/usernames, which are discoverable via GitHub's public API for public orgs/teams.

### Likelihood Explanation
This requires: (1) a multi-org Shipit deployment (`secrets.github` keyed by org) where at least one configured organization intentionally omits `webhook_secret` (documented as optional), and (2) the target organization/team already exists in Shipit's database (synced via a prior legitimate `membership`/OAuth sync) so `find_or_create_by!(github_id:)` resolves to the real team. Both preconditions are plausible in real deployments (e.g., a staging/dev org with no secret configured alongside a production org), but are configuration-dependent rather than universal, so exploitability varies by deployment.

### Recommendation
Bind signature verification to the same organization value the handler will act on: derive `repository_owner` (or an equivalent organization identifier) from the same field the handler trusts (`params.organization.login` for `membership` events), and reject requests where `repository.owner.login` and `organization.login` disagree. Additionally, treat "no `webhook_secret` configured" as a hard misconfiguration warning rather than an automatic pass-through, or require verification against the specific organization asserted by the handler-relevant field, not an attacker-chosen alternate field.

### Proof of Concept
```ruby
test "membership event with mismatched repository.owner vs organization.login writes to the wrong org's team" do
  # Org A has no webhook_secret configured; Org B is the real target org/team.
  Shipit.stubs(:github).with(organization: "org-a-no-secret").returns(
    Shipit::GitHubApp.new("org-a-no-secret", {}) # no webhook_secret
  )
  team = shipit_teams(:org_b_team) # belongs to organization "org-b"
  member = shipit_users(:org_b_member)
  team.add_member(member)

  request.headers['X-Github-Event'] = 'membership'
  request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # attacker-controlled, unverifiable, irrelevant since org A has no secret

  body = {
    action: 'removed',
    repository: { owner: { login: 'org-a-no-secret' } }, # used only by verify_signature
    organization: { login: 'org-b' },                     # used by MembershipHandler
    team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
    member: { login: member.login }
  }.to_json

  assert_difference -> { team.reload.members.count }, -1 do
    post :create, body:, as: :json
  end
  assert_response :ok
end
```
Assert both sides of the binding before/after: `repository_owner` (org A, no-secret) used by `verify_signature` differs from `params.organization.login`/team owner (org B) mutated by `MembershipHandler`, and the test shows the write against org B succeeds despite verification only ever checking org A's (absent) secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
