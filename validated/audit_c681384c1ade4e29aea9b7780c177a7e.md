### Title
Cross-organization Team membership write via unchecked `team.id` in `membership` webhook - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a `membership` webhook body solely against `params['organization']['login']` (via `repository_owner`), while `MembershipHandler#find_or_create_team!` looks up/mutates a `Team` by `params['team']['id']` without ever checking that the team's `organization` matches the org that signed the request. An org that has its own legitimately-configured GitHub App/webhook_secret in Shipit can forge a `membership` event naming its own org in the `organization` field (so signature verification passes with its own secret) while pointing `team.id` at a `Team` record that belongs to a different organization, causing `Membership` rows to be created/deleted for that foreign team.

### Finding Description
The provenance binding this endpoint is supposed to enforce is: `organization whose webhook_secret verified request body == organization owning params['team']`. Tracing the code:

- `verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) [2](#0-1) . This only checks that the *signature* is valid for whichever org's `login` appears in the JSON body — it never inspects `params['team']` at all.
- `MembershipHandler` independently parses `params.team.id`/`params.organization.login` via its own `ExplicitParameters` schema and calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` [3](#0-2) . Critically, the block only runs on **creation**; when a `Team` with that `github_id` already exists (e.g. previously synced from the real victim org), it is looked up and returned as-is, and `team.add_member`/`team.members.delete` is executed against it regardless of which org's signature validated the request [4](#0-3) .

Exploit flow: an attacker who legitimately administers "org-a" in a multi-org Shipit deployment (each org has its own `webhook_secret` per `docs/setup.md`'s "Using Multiple Github Applications" section) sends `POST /webhooks` with `X-Github-Event: membership`, a body containing `"organization":{"login":"org-a"}` and signs it with org-a's own `webhook_secret`. `verify_signature` resolves `Shipit.github(organization: 'org-a')` and successfully verifies, since the attacker legitimately possesses org-a's secret. The same body's `team` object sets `id` to the numeric GitHub team ID of an existing `Team` record belonging to victim "org-b" (team IDs are discoverable via GitHub's public API). Because that `Team` already exists in Shipit's database (synced from a prior legitimate org-b webhook), `find_or_create_by!` finds it and skips the creation block, leaving `team.organization` as `org-b`, then executes `team.add_member(User.find_or_create_by_login!(params.member.login))` for an attacker-chosen GitHub login, or removes an existing member.

No existing guard prevents this: `drop_unhandled_event` only checks the event type is handled [5](#0-4) ; `verify_signature` never cross-checks `team` against `organization`; the `ExplicitParameters` schema for `MembershipHandler` only validates types/presence, not ownership [6](#0-5) ; and `Team.find_or_create_by!` has no `organization:` clause in its lookup, only in the create block.

### Impact Explanation
A successful forged request writes/removes a `Membership` row on a `Team` belonging to a different, victim organization than the one whose secret authenticated the request. Because `User#authorized?` gates general Shipit login/authorization on membership in `Shipit.github_teams` (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`) [7](#0-6) , if the targeted foreign `Team` is one of the configured `oauth.teams` used for authorization, this is escalation into `Shipit.github_teams` authorization for an attacker-controlled GitHub login — matching the High severity category ("escalation into `Shipit.github_teams` authorization"). The attack is repeatable for any team whose numeric `github_id` the attacker can learn, across any org configured in the Shipit instance, as long as the corresponding `Team` row already exists.

### Likelihood Explanation
This requires the attacker to already control a legitimately-provisioned GitHub App/webhook_secret for *some* organization in a multi-tenant Shipit deployment (per `docs/setup.md`'s multi-org config) — i.e., the attacker must be an admin of at least one org onboarded to the shared Shipit instance, not merely "any internet user" with zero relationship to Shipit. It also requires the victim `Team` record to pre-exist in Shipit's database (created via a prior legitimate `membership` webhook from the victim org) and the attacker to know/guess its numeric `github_id`. These are real but non-trivial preconditions specific to multi-org Shipit deployments; single-org deployments (the default) are not exposed since there is only one `webhook_secret`/org.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that an existing `Team`'s `organization` matches `params.organization.login` before mutating membership (or scope the lookup with `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and/or have `WebhooksController#verify_signature` cross-check that `params['team']` (when present) refers to a team under the same organization that signed the request, rejecting mismatches with `head(422)`.

### Proof of Concept
```ruby
test "membership webhook cannot mutate a team belonging to a different organization" do
  # Two orgs each with their own GithubApp config/webhook_secret
  Shipit.stubs(:github_app_config).with('org-a').returns(webhook_secret: 'secret-a')
  Shipit.stubs(:github_app_config).with('org-b').returns(webhook_secret: 'secret-b')

  victim_team = Team.create!(github_id: 555, organization: 'org-b', slug: 'admins', name: 'Admins', api_url: 'https://api.github.com/teams/555')

  body = {
    action: 'added',
    team: { id: 555, name: 'Admins', slug: 'admins', url: 'https://api.github.com/teams/555' },
    organization: { login: 'org-a' }, # signed org, NOT org-b
    member: { login: 'attacker-controlled-login' }
  }.to_json

  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', 'secret-a', body)

  post '/webhooks', params: body, headers: {
    'X-Github-Event' => 'membership',
    'X-Hub-Signature' => signature,
    'Content-Type' => 'application/json'
  }

  # Binding under test: organization that verified signature ('org-a') == organization owning mutated team
  assert_equal 'org-b', victim_team.reload.organization
  # This assertion demonstrates the violation: membership was written to org-b's team
  # despite the request being authenticated only by org-a's secret.
  assert victim_team.members.exists?(login: 'attacker-controlled-login')
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end
```

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
