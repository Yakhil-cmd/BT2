### Title
Membership webhook can add an unauthorized user to a pre-existing `Team` regardless of which organization actually owns it - (`File: app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`find_or_create_team!` looks up a `Team` solely by GitHub `team.id`, and only sets `team.organization` inside the `find_or_create_by!` block, which only runs on creation. For a `Team` that already exists (seeded either by a prior webhook or by `Team.find_or_create_by_handle`/`rake teams:fetch`), the handler never checks that the currently-authenticated `params.organization.login` matches the persisted `team.organization`, allowing any onboarded-but-unrelated GitHub organization to add or remove members on a team it does not own.

### Finding Description
Binding that must hold for any mutation of a pre-existing team to be legitimate: `params.organization.login == team.organization`.

Trace:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) verifies the HMAC signature using `Shipit.github(organization: repository_owner)`, and for membership events `repository_owner` falls back to `params.dig('organization', 'login')` (line 61) because there is no `repository` key in a membership payload. This means the signature only proves the payload was signed with the webhook secret configured for whatever organization is *named inside the payload itself* - i.e. it proves "this request really came from GitHub for org X", where X is attacker-controlled input, not proof that X owns the target team. [1](#0-0) [2](#0-1) 

- `MembershipHandler#find_or_create_team!` (`app/models/shipit/webhooks/handlers/membership_handler.rb:38-43`) does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }`. The block only executes when a new record is being created; for an existing `Team` row, `team.organization` is left untouched and is never compared to `params.organization.login`. [3](#0-2) 

- `process` then calls `team.add_member(member)` / `team.members.delete(member)` unconditionally (lines 26-33), with no re-check of ownership. [4](#0-3) 

Exploit flow: Assume org "shopify" already has a `Team` row (`organization: 'shopify', github_id: N`), created either from an earlier legitimate `membership` webhook or via `Team.find_or_create_by_handle`/`rake teams:fetch` (`app/models/shipit/team.rb:18-27`), which is the documented, trustworthy way to seed teams from `secrets.github.oauth.teams`. [5](#0-4) 

If the attacker controls (or administers) any other GitHub organization that Shipit is also configured to accept webhooks from (e.g. "cyclimse", with its own `webhook_secret` in `secrets.yml`), they can compute a valid `X-Hub-Signature` for that org and POST an arbitrary JSON body to `/webhooks` with `X-Github-Event: membership`, setting:
- `organization.login = "cyclimse"` (so `verify_signature` picks the correct, attacker-known secret)
- `team.id = N` (the real, already-existing `shopify` team's `github_id`)
- `action = "added"`, `member.login = <attacker's own GitHub login>`

Because `find_or_create_team!` finds the team by `github_id` alone and skips the `organization` assignment on the existing-record path, and `process` never compares `params.organization.login` ("cyclimse") to `team.organization` ("shopify"), `team.add_member(member)` executes and inserts a `Membership` row linking the attacker's `User` to the "shopify" team - despite the request only ever being authenticated as belonging to "cyclimse".

None of the existing guards catch this: `verify_signature` only proves *a* valid org signed the request, not that it is the *correct* org for the target team; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape, not cross-organization identity; there is no `require_permission!`/`User#authorized?` check inside the webhook handler.

### Impact Explanation
This is an authorization-bypass: membership in a `Team` record directly feeds `User#authorized?` (`app/models/shipit/user.rb:80-82`), which gates access when `Shipit.github_teams` is configured, and `Team#members` also drives deploy/stack permissioning wherever `Shipit.github_teams`-restricted access is used. An attacker who controls or administers any single GitHub organization onboarded to the same Shipit instance can grant themselves (or any GitHub login) membership in a completely different, more-privileged team belonging to another organization, escalating into `Shipit.github_teams` authorization for that unrelated tenant. It is repeatable against any team whose numeric `github_id` the attacker can guess/enumerate, and can also be used to *remove* legitimate members (`action: 'removed'`), causing denial of legitimate access. This matches the "High: escalation into `Shipit.github_teams` authorization" impact category, and could be Critical if that authorization gates deploy/merge actions in the host application.

### Likelihood Explanation
Requires: (1) the Shipit deployment to be multi-tenant, i.e. `Shipit.github_teams` used for authorization and more than one GitHub organization configured with webhook secrets in `secrets.yml` (a documented, supported configuration), and (2) the attacker to be an admin/owner of at least one such onboarded organization (or otherwise obtain its `webhook_secret`) - not a Shipit operator or a member of the target team. Given that, the attack costs a single crafted HTTP POST with a known team `github_id`, which is easy to guess for public teams via GitHub's org/team API and does not require any Shipit secret beyond the attacker's own org's webhook secret. Fully repeatable and scriptable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that `params.organization.login` matches the persisted `team.organization` for pre-existing teams, and raise/drop the event (return 422 or no-op) if they diverge, e.g.:
```ruby
def find_or_create_team!
  team = Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
  raise ArgumentError, "Team organization mismatch" unless team.organization == params.organization.login
  team
end
```
Alternatively, scope the `find_or_create_by!` lookup to `github_id: params.team.id, organization: params.organization.login` so a cross-organization ID collision can never resolve to the wrong record.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb
test "membership webhook signed by an unrelated organization can add a member to a pre-existing team it does not own" do
  team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: <N>
  assert_equal 'shopify', team.organization

  payload = {
    action: 'added',
    team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
    organization: { login: 'cyclimse' }, # different, but independently-verified org
    member: { login: 'attacker' }
  }

  assert_difference -> { Shipit::Membership.count }, 1 do
    Shipit::Webhooks::Handlers::MembershipHandler.new(payload.as_json).call
  end

  team.reload
  assert_equal 'shopify', team.organization # binding still broken: org never re-validated
  assert team.members.exists?(login: 'attacker')
end
```
This demonstrates `params.organization.login` ("cyclimse") diverging from `team.organization` ("shopify") while the mutation (`Membership` creation) still succeeds, confirming the missing authorization check.

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

**File:** app/models/shipit/team.rb (L17-27)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end

      def fetch_and_create_from_github(organization, slug)
        return unless github_team = find_team_on_github(organization, slug)

        create!(github_team:, organization:)
      end
```
