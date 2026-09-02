### Title
Cross-organization team-membership forgery via a no-secret org lets an attacker join a `Shipit.github_teams`-bound Team and pass `User#authorized?` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb], [File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/user.rb])

### Summary
In a multi-organization Shipit configuration, webhook signature verification is scoped to whichever organization the attacker names in the payload (`repository_owner`/`organization.login`), while `MembershipHandler` resolves the target `Team` purely by the GitHub-supplied `team.id`, with no check that the payload's `organization.login` matches the team's owning organization. This lets a webhook that is only "verified" by a no-secret org add an arbitrary attacker-chosen GitHub login to a `Team` record that actually belongs to a different, secured org and is a member of `Shipit.github_teams`, so a subsequent legitimate OAuth login for that login makes `Shipit::User#authorized?` return `true`.

### Finding Description
The intended binding is: `current_user.authorized? == true` **iff** GitHub's owning organization (verified via that org's `webhook_secret`) sent a `membership` "added" event for that same organization's team. The code breaks this equality:

- `Shipit.github(organization: repository_owner)` in `WebhooksController#verify_signature` looks up the GitHub App config keyed by the `organization.login` value taken directly from the attacker-controlled payload (`repository_owner` falls back to `params.dig('organization', 'login')` when there is no `repository` key, which is exactly the case for `membership` events). [1](#0-0) [2](#0-1) 
- `GitHubApp#verify_webhook_signature` unconditionally returns `true` if that organization's config has no `webhook_secret` set: `return true unless webhook_secret`. [3](#0-2) 
- Multi-organization configuration is a documented, supported mode where `webhook_secret` is explicitly optional per organization. [4](#0-3) 
- `MembershipHandler#find_or_create_team!` resolves the `Team` record solely by `github_id: params.team.id`, with no validation that `params.organization.login` matches the team's stored `organization`: `Team.find_or_create_by!(github_id: params.team.id) do |team| ... end` — the block (which sets `team.organization`) only executes when a **new** record is created, so for an already-existing team it is a no-op, and the lookup key is entirely organization-agnostic. [5](#0-4) 
- `process` then creates/finds the attacker-named user via `User.find_or_create_by_login!(params.member.login)` and calls `team.add_member(member)`, writing a `Membership` row. [6](#0-5) 
- `Shipit.github_teams` resolves the authorized teams from the *default/first* configured organization's `oauth.teams` list, fetching each team's real `github_id` from GitHub once via `Team.find_or_create_by_handle`. [7](#0-6) 
- `User#authorized?` checks membership purely by database `Team#id`, derived from that already-resolved `github_id` match: `teams.where(id: Shipit.github_teams.map(&:id)).exists?`. [8](#0-7) 

**Exploit flow:** Shipit is configured with (at least) two GitHub organizations: `orgA` (owns the authorized team, has a real `webhook_secret`, and is the first key in `secrets.github` so its `oauth.teams` populates `Shipit.github_teams`) and `orgB` (configured but with `webhook_secret` left blank, per the documented "optional" setting). The attacker, knowing or guessing the numeric `github_id` of `orgA`'s authorized team (team IDs are ordinary GitHub object IDs, not secrets, and may be visible via public API responses, prior deliveries, or brute force), POSTs to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{"action":"added","team":{"id":<orgA_team_github_id>,"name":"x","slug":"x","url":"x"},
 "organization":{"login":"orgB"},"member":{"login":"attacker_login"}}
```
with any/garbage `X-Hub-Signature`. Because `repository_owner` resolves to `"orgB"` and `orgB` has no `webhook_secret`, `verify_signature` passes unconditionally. `MembershipHandler` then finds the *existing* Team record for `orgA`'s authorized team (matched by `github_id`) and adds `attacker_login` as a member. The attacker subsequently performs an ordinary, real OAuth login to Shipit with their own GitHub account (`attacker_login`); the resulting `User` row is matched/created and now already has the forged `Membership`, so `authorized?` returns `true` and `session[:user_id]`/`current_user` is fully authorized — without ever being vetted by `orgA`'s secret or GitHub's real team membership.

Existing guards do not prevent this: `drop_unhandled_event` and the `ExplicitParameters` schema only validate event type/shape, not organization ownership; `verify_signature` verifies a signature but against the wrong (attacker-chosen) organization's config; nothing in `MembershipHandler` or `Team` cross-checks `organization.login` against the team's true organization before mutating membership.

### Impact Explanation
A single forged, effectively-unsigned HTTP POST from an unprivileged attacker who does not hold `orgA`'s webhook secret can grant themselves membership in a Team that is part of `Shipit.github_teams`, and a normal subsequent OAuth login with their own real GitHub account then satisfies `User#authorized?`. This is escalation into `Shipit.github_teams` authorization scope, granting full authenticated access to Shipit (stacks, deploys, rollbacks, merges, task output) as if they were a verified member of the protected organization's team — matching the "High" impact category (escalation into `Shipit.github_teams` authorization). The attack is repeatable for any attacker-chosen GitHub login and, since it only depends on knowing a target team's `github_id`, is repeatable across any number of attacker accounts once that ID is known.

### Likelihood Explanation
This requires: (1) a multi-organization Shipit deployment, (2) at least one configured organization with `webhook_secret` left unset (explicitly documented as optional, a plausible real-world misconfiguration/oversight, not a hardening bypass of a mandatory control), and (3) knowledge of the numeric `github_id` of the target team. Given (2) is a supported and undocumented-as-dangerous default, and (3) is a non-secret, discoverable/guessable identifier, the preconditions are realistic though not universal — this is not exploitable against a single-organization deployment where the only org's secret is unset (in that case the "no-secret org" and "owning org" are the same, which is a separate, already-known risk of operating without a webhook secret at all). The cross-organization confusion specifically bypassing a *different, properly-secured* org's protection is the novel and non-obvious part of this bug.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` **and** `organization` (`Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login.downcase)`), and reject/no-op if an existing team with that `github_id` has a different `organization` than the payload claims. Additionally, consider requiring `webhook_secret` to be present for every configured organization (or at minimum for any organization whose teams are referenced in `oauth.teams`), and validate at handler-time that `verify_signature`'s resolved organization equals the team's canonical organization before mutating memberships.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_membership_cross_org_test.rb
require 'test_helper'

module Shipit
  class MembershipCrossOrgForgeryTest < ActionController::TestCase
    tests WebhooksController

    setup do
      @routes = Shipit::Engine.routes
      # orgA: owns the real authorized team, has a webhook_secret configured
      # orgB: configured org with NO webhook_secret (optional per docs)
      Shipit.stubs(:github_teams).returns([shipit_teams(:shopify_developers)]) # simulates orgA's authorized team
    end

    test "membership webhook 'verified' by a no-secret org cannot grant membership to another org's authorized team" do
      target_team = shipit_teams(:shopify_developers) # belongs to orgA, github_id already resolved
      attacker_login = 'evil_attacker'

      # Simulate orgB's app having no webhook_secret -> verify_webhook_signature returns true unconditionally
      Shipit.stubs(:github).with(organization: 'orgb').returns(
        stub(verify_webhook_signature: true)
      )

      Shipit.github.api.stubs(:user).with(attacker_login).returns(
        stub(id: 999_999, login: attacker_login, name: 'Evil', email: 'e@example.com',
             avatar_url: 'https://x', url: 'https://x')
      )

      request.headers['X-Github-Event'] = 'membership'
      request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # bogus, irrelevant because org has no secret

      payload = {
        action: 'added',
        team: { id: target_team.github_id, name: target_team.name, slug: target_team.slug, url: target_team.api_url },
        organization: { login: 'orgB' }, # attacker-chosen org used only for signature-scope lookup
        member: { login: attacker_login }
      }.to_json

      assert_no_difference -> { Membership.count } do
        post :create, body: payload, as: :json
      end
      # EXPECTED (secure): membership must NOT be created because 'orgB' did not verify with a real secret
      # and does not own `target_team`.
      # ACTUAL (vulnerable code today): Membership IS created, and:

      attacker = User.find_by(login: attacker_login)
      assert_equal false, attacker.teams.where(id: Shipit.github_teams.map(&:id)).exists?,
        "attacker must not be a member of an org's authorized team via a webhook that org never verified"
    end
  end
end
```
This test encodes the binding as an explicit equality (`attacker.teams.where(id: Shipit.github_teams.map(&:id)).exists? == false` unless the owning org's secret verified the add) and demonstrates that, with current code, the forged cross-organization webhook creates the `Membership` and would make a subsequent real OAuth login for `attacker_login` return `authorized? == true`.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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
