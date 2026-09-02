### Title
Cross-organization team membership deletion via forged `membership` webhook - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#process` deletes a `Membership` row for `action: 'removed'` using only `params.team.id` to look up the `Team`, without verifying that the webhook's authenticated organization matches `team.organization`. Because `WebhooksController#verify_signature` selects which org's `webhook_secret` to check based on the payload's own `organization.login` field, any org configured in the multi-org setup can sign a `membership` `removed` event naming a team `github_id` belonging to a *different* org and revoke a victim's Shipit team membership.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't: `verified_organization (used to select webhook_secret) == team.organization (owner of the team.github_id referenced in the payload)`.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` via `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . `membership` events carry no top-level `repository` key, so this falls back to the attacker-controlled `organization.login` field in the payload.
2. `Shipit.github(organization: repository_owner)` then loads that org's own `webhook_secret` and `verify_webhook_signature` succeeds because the attacker signs with the secret of the org they legitimately control [2](#0-1) [3](#0-2) .
3. `MembershipHandler#process` looks up the team purely by `params.team.id` (`github_id`), ignoring `params.organization.login` entirely for lookup or validation, then executes `team.members.delete(member)` for `action == 'removed'` [4](#0-3) .
4. Since the team already exists (it's a real, tracked team in `Shipit.github_teams`), `find_or_create_by!`'s block (which sets `team.organization`) never runs, so the lookup silently succeeds against the victim org's pre-existing `Team` record regardless of which org's secret verified the request.
5. `Team#add_member`/`members.delete` operate directly on the `has_many :memberships` association without any organization-equality check [5](#0-4) .

No other guard intervenes: `drop_unhandled_event` only checks the event type is registered, `ExplicitParameters` only validates payload shape, and there is no `force_github_authentication`/`require_permission!` check in the webhook path since it is unauthenticated by design (it uses HMAC signature instead of session/user auth).

### Impact Explanation
An attacker who administers or otherwise knows the `webhook_secret` for *any* org configured in a multi-org Shipit deployment can forge a `membership` `removed` webhook naming the `github_id` of a team belonging to a different org, deleting the victim's `Membership` row and stripping their `Shipit.github_teams` authorization without any action by, or notification to, the victim's real organization or GitHub itself. This is a cross-tenant authorization write not scoped to the attacker's own org — matching the "escalation/de-escalation into `Shipit.github_teams` authorization" High-severity category (here used destructively to revoke access, and by symmetry the `added` branch could grant unauthorized cross-org membership too, which is Critical-adjacent). It is fully repeatable against any team `github_id` and any victim user known to the attacker, is not confined to the attacker's own repositories/stacks, and requires no Shipit session or API token.

### Likelihood Explanation
Requires a multi-org Shipit configuration where the attacker legitimately controls at least one configured org's webhook (a realistic multi-tenant deployment scenario), knowledge of a target team's numeric GitHub `id` (discoverable via GitHub's team API/UI) and a victim's GitHub login (public). No Shipit secrets, sessions, or API tokens are needed — only the attacker's own webhook secret, which they legitimately possess for their own org. Cost is a single crafted HTTP POST to `/webhooks`.

### Recommendation
In `MembershipHandler#process`, validate that the authenticated/verified organization for the request matches `team.organization` before mutating membership (e.g., pass the verified organization from the controller into the handler, or re-derive it and compare against `team.organization`, aborting/raising if they differ). More generally, `WebhooksController#verify_signature`'s organization derivation should not trust an attacker-controlled `organization.login`/`repository.owner.login` field to select which secret to validate against for events that reference an existing team scoped to a different org.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/membership_handler_test.rb` conceptually, though tests are out-of-scope for repo edits per rules — described for reproduction purposes only):
```ruby
test "#process does not remove membership when payload organization differs from team.organization" do
  victim_org_team = shipit_teams(:committers) # organization: 'shopify', github_id: 1234
  victim = shipit_users(:walrus)
  victim_org_team.add_member(victim)

  payload = {
    'action' => 'removed',
    'team' => { 'id' => victim_org_team.github_id, 'name' => victim_org_team.name, 'slug' => victim_org_team.slug, 'url' => victim_org_team.api_url },
    'organization' => { 'login' => 'attacker-owned-org' }, # verified via attacker's own webhook_secret, not 'shopify'
    'member' => { 'login' => victim.login }
  }

  assert_no_difference -> { Membership.count } do
    Shipit::Webhooks::Handlers::MembershipHandler.call(payload)
  end
end
```
Before the fix: `Membership.count` decreases by 1 even though `payload['organization']['login']` ('attacker-owned-org') != `victim_org_team.organization` ('shopify'), demonstrating the broken provenance binding.

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

**File:** app/models/shipit/team.rb (L7-43)
```ruby
    has_many :memberships
    has_many :members, class_name: :User, through: :memberships, source: :user

    has_many :github_hooks,
             -> { where(event: REQUIRED_HOOKS) },
             foreign_key: :organization,
             primary_key: :organization,
             class_name: 'GithubHook::Organization',
             inverse_of: false

    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end

      def fetch_and_create_from_github(organization, slug)
        return unless github_team = find_team_on_github(organization, slug)

        create!(github_team:, organization:)
      end

      def find_team_on_github(organization, slug)
        gh_api = Shipit.github(organization:).api
        teams = Shipit::OctokitIterator.new(github_api: gh_api) { gh_api.org_teams(organization, per_page: 100) }
        teams.find { |t| t.slug == slug }
      rescue Octokit::NotFound
      end
    end

    def handle
      "#{organization}/#{slug}"
    end

    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
