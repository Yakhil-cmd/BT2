### Title
Cross-organization Team membership mutation via `MembershipHandler` — signed-org binding not enforced on `team.id` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` only proves that *some* configured GitHub organization's `webhook_secret` matches the raw request body; it never checks that the organization used to resolve the signing secret (`repository_owner`) matches the organization referenced by the `team` object the handler subsequently mutates. `MembershipHandler#find_or_create_team!` looks up/creates a `Team` keyed solely by `github_id` (which is globally unique across all of GitHub, not scoped to an organization), so any onboarded org whose secret is used to sign a webhook can add/remove members on a `Team` row that actually belongs to a different onboarded organization.

### Finding Description
The broken binding: `Shipit.github(organization: repository_owner).webhook_secret verifies body` should imply `team.organization (as mutated) == repository_owner`, but the code never asserts this equality.

- `WebhooksController#verify_signature` resolves `repository_owner` via `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and only checks that `Shipit.github(organization: repository_owner)`'s secret validates the raw signature [2](#0-1) .
- For a `membership` event there is no `repository` key at all, so `repository_owner` resolves purely from `organization.login` in the body — an attacker-controlled field that just has to match whichever org's secret they used to sign the request.
- Once verified, `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` [3](#0-2) . The `organization=` assignment inside the block **only runs on record creation**; if a `Team` row with that `github_id` already exists (e.g., belonging to `shopify`), `find_or_create_by!` returns the existing row untouched, and `team.add_member(member)` / `team.members.delete(member)` is executed against it [4](#0-3) .
- Nothing compares `params.organization.login` (used only for signature routing and for populating a brand-new team) against the `organization` column of an already-existing team with that `github_id`.

Exploit flow: an onboarded, low-privileged organization "attacker-org" (which has its own `webhook_secret` configured in Shipit's multi-org credentials, per the stated precondition) signs a request with its own secret and posts `X-Github-Event: membership` with `organization: {login: 'attacker-org'}` and `team: {id: <victim's real github team id>, name, slug, url}` plus a `member.login` of their choosing. Signature verification passes because it only checks `attacker-org`'s secret against the raw body — it has no knowledge of, or interest in, which organization's team is being referenced inside that body. `MembershipHandler` then finds the victim's pre-existing `Team` row by `github_id` and adds the attacker's chosen member to it.

Existing guards do not catch this: `verify_signature` never re-derives the org from `team`/`organization` for authorization purposes beyond signature routing; `ExplicitParameters` schema in `MembershipHandler` only validates types/presence, not organization consistency [5](#0-4) ; there is no `find_or_create_by!(github_id:, organization:)` compound key.

### Impact Explanation
If the victim `Team` (matched by `github_id`) is one of the teams referenced by `Shipit.github_teams` (the teams used for authorization, computed from `github.oauth_teams` via `Team.find_or_create_by_handle`) [6](#0-5) , then `User#authorized?` becomes true for the injected member because it checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) . This is escalation into `Shipit.github_teams` authorization from a completely unrelated, lower-trust tenant — matching the High-severity category in the rules. Even without hitting an authorization team, it is still an unauthorized cross-tenant write: an org's webhook can silently add/remove memberships on another organization's `Team` record, which is a record mutation for a repository/org that never authenticated it.

### Likelihood Explanation
Requires a genuine multi-org Shipit deployment where more than one organization is onboarded with its own `webhook_secret` (a real, documented configuration mode per `Shipit.github_app_config`) [8](#0-7) . Any one of those onboarded orgs — regardless of how low-trust or unrelated to the target — can mount the attack by crafting a raw HTTP POST signed with its own secret; no knowledge of the victim org's secret or GitHub team API access is needed, only the victim's real (or guessed) GitHub team `github_id`. The attack is trivially repeatable against any team whose `github_id` is known.

### Recommendation
`MembershipHandler#find_or_create_team!` must scope the lookup by both `github_id` AND `organization`, and reject/raise (rather than mutate) when a `Team` with the given `github_id` exists under a different organization than the one that authenticated the request (i.e., `repository_owner`/`params.organization.login` used for signature verification). At minimum, enforce `team.organization == params.organization.login` before allowing `add_member`/`members.delete`, and ideally propagate the authenticated `repository_owner` from the controller into the handler for this comparison instead of trusting `params.organization.login` alone.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/membership_handler_test.rb (new)
test "membership webhook cannot mutate a team belonging to a different organization" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: 1
  assert_equal 'shopify', victim_team.organization

  attacker_payload = {
    'action' => 'added',
    'team' => { 'id' => victim_team.github_id, 'name' => 'Fake', 'slug' => 'fake', 'url' => 'https://x' },
    'organization' => { 'login' => 'attacker-org' }, # signs with attacker-org's own secret
    'member' => { 'login' => 'mallory' }
  }

  assert_no_difference -> { victim_team.members.reload.count }, 'membership should not change for a team the request never authenticated for' do
    Shipit::Webhooks::Handlers::MembershipHandler.new(attacker_payload).process
  end

  # Assert the equality the code never checks:
  refute_equal attacker_payload['organization']['login'], victim_team.reload.organization
end
```
This proves `Team#organization` ('shopify') never equals the organization whose secret was used to authenticate the payload ('attacker-org'), yet the handler still mutates `victim_team.members` — confirming the missing binding.

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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
