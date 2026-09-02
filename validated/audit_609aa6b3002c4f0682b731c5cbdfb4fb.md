### Title
Cross-organization `Team.find_or_create_by!(github_id:)` lets an attacker-controlled org's membership webhook add members to another org's `Shipit.github_teams`-authorized team - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` looks up (or creates) a `Team` solely by the numeric `team.id` field from the webhook payload, with no check that the requesting organization (the one whose secret verified the webhook) matches the `Team#organization` already stored on that record. In a multi-org Shipit deployment, an attacker who administers their own GitHub org (and thus knows its own valid `webhook_secret`) can forge a `membership` `added` event for their own org with `team.id` equal to the `github_id` of a pre-existing `Team` row that belongs to a *different* org and is one of the handles configured in `Shipit.github_teams`, causing `team.add_member(member)` to add the attacker to that team's `members`.

### Finding Description
The broken binding is: `Team.find_or_create_by!(github_id: params.team.id).organization` is implicitly assumed to equal `params.organization.login`, but the code never enforces or checks this equality — `app/models/shipit/webhooks/handlers/membership_handler.rb:38-43`:

```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
```

The block (which sets `organization`) only executes on **create**. If a `Team` record with that `github_id` already exists (e.g., previously created legitimately for `shopify/developers`, `github_id: 1`, per `test/fixtures/shipit/teams.yml:3-9`), `find_or_create_by!` returns the **existing** record untouched, regardless of which organization's webhook triggered the lookup.

Signature verification (`app/controllers/shipit/webhooks_controller.rb:24-30`) only checks that the payload was signed by *some* configured org's `webhook_secret`, selected via `repository_owner` which, for `membership` events (no `repository` key), falls back to `params.dig('organization', 'login')` (`app/controllers/shipit/webhooks_controller.rb:59-62`). Both `organization.login` and `team.id` are fully attacker-controlled payload fields — verification proves only "this JSON blob was signed by org X's secret," not that `team.id` belongs to org X.

Attacker's exact request: attacker administers `attacker-org` (a legitimately configured GitHub App/org in Shipit's multi-org `secrets.yml`, per `docs/setup.md:182-209`), knows `attacker-org`'s real `webhook_secret`, and sends:
```json
{
  "action": "added",
  "team": {"id": 1, "name": "Developers", "slug": "developers", "url": "https://example.com/shopify/developers"},
  "organization": {"login": "attacker-org"},
  "member": {"login": "attacker-login"}
}
```
signed with `attacker-org`'s HMAC secret. `verify_signature` passes because `attacker-org` is a real, correctly-secreted tenant. `find_or_create_team!` then resolves `github_id: 1` to the existing `shopify_developers` Team (an org unrelated to `attacker-org`), and `team.add_member(member)` (`app/models/shipit/team.rb:41-43`) inserts a `Membership` linking the attacker's `User` to that team.

Downstream, `User#authorized?` (`app/models/shipit/user.rb:80-82`) does:
```ruby
@authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
```
and `force_github_authentication` / `require_permission!` rely on it (`app/controllers/concerns/shipit/authentication.rb:20-34`, `app/controllers/shipit/api/base_controller.rb`). If `shopify/developers` is configured in `Shipit.github_teams` (`docs/setup.md:139-141`), the attacker is now recognized as an authorized Shipit user/API actor for the entire application, despite never being a member of `shopify`'s actual GitHub team.

None of the listed guards prevent this: `verify_signature` validates only the signer, not payload-organization/team consistency; `ExplicitParameters` only enforces types/presence, not cross-field integrity; `drop_unhandled_event` doesn't apply (membership is handled); there is no `Team` validation tying `github_id` to `organization` at write time on the update path.

### Impact Explanation
This is a High-severity escalation into `Shipit.github_teams` authorization: an unprivileged attacker who merely controls one legitimately-configured tenant org in a multi-org Shipit deployment can grant themselves membership in *any other tenant's* authorization-gating team by guessing/observing that team's numeric GitHub team ID (these leak via GitHub's public/semi-public team APIs or via observed webhook payloads) and replaying it in a self-signed membership event. The action is repeatable for any `github_id` and grants full UI login/authorization (`force_github_authentication`) and any API operations gated by team-based checks, matching the "escalation into Shipit.github_teams authorization" impact class explicitly listed as High.

### Likelihood Explanation
Requires: (1) Shipit deployed with the multi-org GitHub App configuration (`docs/setup.md:182-209`), (2) attacker legitimately controls at least one configured org/app in that deployment (their own `webhook_secret`), (3) knowledge of the target team's `github_id` (obtainable via GitHub's team API or observed traffic), and (4) a pre-existing `Team` row for the target `github_id` (created the first time that team's real membership webhook fired, which is normal operational state, not attacker-controlled). Given these preconditions, the attack is cheap (a single crafted, self-signed HTTP POST) and fully repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization`, and fail (or re-associate only via a trusted admin path) when a `github_id` collision maps to a different `organization`:
```ruby
def find_or_create_team!
  team = Team.find_by(github_id: params.team.id)
  if team && team.organization != params.organization.login.downcase
    raise ArgumentError, "team #{params.team.id} does not belong to organization #{params.organization.login}"
  end
  team || Team.create!(github_team: params.team, organization: params.organization.login)
end
```
Additionally, add a uniqueness validation on `Team` for `[:github_id, :organization]` and consider validating that `params.organization.login` matches the org whose secret verified the webhook (already implicit, but should be asserted explicitly here too) so a `Team`'s `github_id` can never silently span organizations.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb (conceptual, no live GitHub)
test "cross-org membership webhook cannot add member to a team belonging to a different org" do
  target_team = shipit_teams(:shopify_developers) # github_id: 1, organization: 'shopify'
  Shipit.stubs(:github_teams).returns([target_team])

  attacker = Shipit::User.find_or_create_by_login!('attacker-login')

  payload = {
    'action' => 'added',
    'team' => { 'id' => target_team.github_id, 'name' => target_team.name,
                'slug' => target_team.slug, 'url' => target_team.api_url },
    'organization' => { 'login' => 'attacker-org' },
    'member' => { 'login' => 'attacker-login' }
  }

  Shipit::Webhooks::Handlers::MembershipHandler.new.call(payload)

  target_team.reload
  # Assert the broken binding: team.organization ('shopify') != payload org ('attacker-org')
  refute_equal 'attacker-org', target_team.organization

  # Exploit assertion: attacker should NOT be a member, but currently is
  refute target_team.members.include?(attacker), "attacker gained membership via unrelated org's webhook"
  refute attacker.authorized?, "attacker gained Shipit.github_teams authorization via cross-org webhook forgery"
end
```
This test demonstrates the equality `target_team.organization == payload['organization']['login']` is false both before and after the call, yet `add_member` still runs, proving the authorization boundary is broken. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```

**File:** test/fixtures/shipit/teams.yml (L1-17)
```yaml
# Read about fixtures at http://api.rubyonrails.org/classes/ActiveRecord/FixtureSet.html

shopify_developers:
  id: 1
  github_id: 1
  organization: shopify
  slug: developers
  name: Developers
  api_url: https://example.com/shopify/developers

cyclimse_cooks:
  id: 2
  github_id: 2
  organization: cyclimse
  slug: cooks
  name: Cooks
  api_url: https://example.com/cyclimse/cooks
```

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
