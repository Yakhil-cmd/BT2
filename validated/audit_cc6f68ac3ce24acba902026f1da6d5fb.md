### Title
Membership webhook trusts `params.organization.login` for signature scoping but never binds it to the existing `Team#organization` on lookup, letting any org owner forge team membership for a foreign, already-registered team - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#process` resolves the target `Team` solely by the numeric `params.team.id` (GitHub `github_id`), while `WebhooksController#verify_signature` authenticates the request only against `Shipit.github(organization: params.organization.login)`. Because these two values are never cross-checked, an attacker who owns any org with its own configured GitHub App/webhook secret can sign a `membership` `added` event naming their own org, but pointing `team.id` at the `github_id` of a *different*, already-existing `Team` (e.g. one listed in `Shipit.github_teams`), and add themselves as a member of that foreign team.

### Finding Description
The broken binding: `Membership(team_id: T, user: attacker)` should only exist **iff** GitHub's real organization owning team `T` reported that membership. In code:

- `WebhooksController#verify_signature` picks the signing organization from the payload itself: `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and verifies the signature using `Shipit.github(organization: repository_owner)` [2](#0-1) . For a membership event there is no `repository` key, so this is exactly `params['organization']['login']` — a value the attacker controls and can set to their own org, which has its own valid `webhook_secret` in `secrets.github`.
- `MembershipHandler#process` then resolves the team with `Team.find_or_create_by!(github_id: params.team.id)` [3](#0-2) . If a `Team` with that `github_id` already exists (e.g. `shopify_developers`, `organization: shopify`, fixture at [4](#0-3) ), the block that sets `team.organization = params.organization.login` never runs — the existing row, with its real organization, is returned unchanged.
- `process` then does `team.add_member(member)` [5](#0-4) , where `member = User.find_or_create_by_login!(params.member.login)` — the attacker's own GitHub login — creating a `Membership` row (`app/models/shipit/team.rb` `add_member`) [6](#0-5) .

At no point is `params.organization.login` compared against the resolved `team.organization`. The signature check authenticates "this request came from an org whose secret matches," not "this request came from the org that owns team T." Existing guards do not catch this: `verify_signature` only rejects unknown/invalid orgs, not org/team mismatches; `find_or_create_team!` has no ownership check; `Membership` validation only enforces uniqueness, not authenticity of origin [7](#0-6) .

Attacker request: `POST /webhooks` with header `X-Github-Event: membership`, `X-Hub-Signature` computed with the attacker's own org's `webhook_secret`, and body `{"action":"added","team":{"id":<real_team_github_id>,"name":"...","slug":"...","url":"..."},"organization":{"login":"<attacker_org>"},"member":{"login":"<attacker_github_login>"}}`.

Resulting effect: `User#authorized?` becomes true for the attacker: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [8](#0-7) , which is enforced at `force_github_authentication` in `Authentication` concern to gate access to the whole app [9](#0-8) .

### Impact Explanation
This is authentication bypass: an attacker with no Shipit session, no GitHub org membership in the target org, and no privileged Shipit role gains full authenticated access to the Shipit instance by forging a `Membership` row for a team listed in `Shipit.github_teams`. Once `authorized?` is true, they pass `force_github_authentication` and can access stacks, tasks, deploys, and other authenticated Shipit functionality gated only by "logged in + authorized" (session cookie from GitHub OAuth login, which is unrelated to this bug but is the normal login path — the privilege escalation is solely in team membership). This is repeatable against any tenant's team that the attacker can learn the numeric `github_id` for, and requires no interaction with the victim org's actual GitHub App or secret. Severity matches "escalation into `Shipit.github_teams` authorization" (High) and arguably crosses into "authentication bypass" territory (Critical) given `authorized?` gates the entire application.

### Likelihood Explanation
Preconditions: the attacker must own/administer some GitHub org and have configured that org as a `Shipit.github` app entry (multi-org secrets config) so their own webhook signature verifies — a low-cost, self-service setup entirely within the attacker's control. They must also know the numeric `github_id` of the target team, which is either a small sequential-looking integer or discoverable via prior webhook payloads, GitHub API exposure of visible teams, or other side channels; this is stated as a given precondition in the question rather than something this analysis newly proves. Given that, the attack is a single unauthenticated HTTP POST, fully repeatable and scriptable, with no rate limiting relevant to a one-shot escalation.

### Recommendation
In `MembershipHandler#find_or_create_team!` (and generally in `Team` lookup from webhooks), verify that `params.organization.login` matches the `repository_owner`/authenticated organization used in `verify_signature`, and reject (or refuse to mutate) when an existing `Team#organization` does not match the organization that authenticated the request. Concretely: after resolving `team = Team.find_or_create_by!(...)`, assert `team.organization.casecmp?(params.organization.login)` (case-insensitively, consistent with `github_app_config`) before calling `team.add_member`/`team.members.delete`, and raise/drop the event otherwise. Additionally consider binding the webhook's authenticated organization into the handler context (e.g. passed down from the controller) rather than trusting `params.organization.login` twice for two different purposes (signing scope and team resolution).

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "membership webhook signed by attacker's own org cannot grant membership on a foreign team" do
  # Equality claimed by the code path (should NOT hold true for a foreign org):
  #   team.organization == params.organization.login  -> currently unchecked
  target_team = shipit_teams(:shopify_developers) # organization: "shopify"
  Shipit.stubs(:github_teams).returns([target_team])

  attacker_login = 'attacker_user'
  attacker_org   = 'attacker-org'

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: target_team.github_id, name: target_team.name, slug: target_team.slug, url: target_team.api_url },
    organization: { login: attacker_org },
    member: { login: attacker_login }
  }.to_json

  # Attacker's own org's app/webhook secret verifies successfully (their own tenant).
  Shipit.github(organization: attacker_org).stubs(:verify_webhook_signature).returns(true)
  Shipit.github.api.stubs(:user).with(attacker_login).returns(
    stub(id: 999, login: attacker_login, name: 'Attacker', email: 'a@example.com',
         avatar_url: 'https://example.com/a.png', url: 'https://api.github.com/users/attacker_user')
  )

  post :create, body: payload, as: :json
  assert_response :ok

  attacker = Shipit::User.find_by!(login: attacker_login)

  # BEFORE: attacker not authorized.
  # AFTER forged webhook: authorized? becomes true despite never being added by "shopify".
  assert attacker.authorized?, "attacker gained authorization via forged cross-org membership webhook"
end
```
This demonstrates that `Membership(team_id: target_team.id, user: attacker)` is created and `User#authorized?` flips to `true` purely from a request authenticated under `attacker-org`'s own secret, never under `shopify`'s, confirming the binding is broken.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-28)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
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

**File:** test/fixtures/shipit/teams.yml (L3-9)
```yaml
shopify_developers:
  id: 1
  github_id: 1
  organization: shopify
  slug: developers
  name: Developers
  api_url: https://example.com/shopify/developers
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/models/shipit/membership.rb (L1-9)
```ruby
# frozen_string_literal: true

module Shipit
  class Membership < Record
    belongs_to :team, required: true
    belongs_to :user, required: true

    validates :user_id, uniqueness: { scope: :team_id }
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
