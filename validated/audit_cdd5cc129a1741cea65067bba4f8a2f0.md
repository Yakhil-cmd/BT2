### Title
Cross-organization team hijack via `membership` webhook - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
The `membership` webhook handler resolves the `Team` record to mutate using only the GitHub-supplied `team.id`, with no check that the team belongs to the organization whose webhook secret produced the request signature. This breaks the trust binding "organization that authenticated == team that is written," allowing an attacker who controls any GitHub organization onboarded to the Shipit instance to add themselves (or anyone) to a `Team` record belonging to a completely different organization — including a team enumerated in `Shipit.github_teams`, which gates authorization for the whole application.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/webhook secret to validate the request against based on `repository_owner`, which for events without a `repository` key (like `membership`) falls back to the event's own `organization.login`: [1](#0-0) [2](#0-1) 

This means the signature check only proves "this request was really sent by organization X's GitHub App" — it says nothing about which `Team` record the payload is allowed to touch. The `MembershipHandler` then processes the event: [3](#0-2) 

`find_or_create_team!` looks the `Team` up (or creates it) solely by `github_id: params.team.id` — a plain integer taken from the attacker-controlled JSON body, with no scoping to `params.organization.login`. GitHub numeric team IDs are not secrets and are trivially observable/enumerable (e.g. via the GitHub API or UI for public/shared teams). If organization X (which the attacker legitimately administers or belongs to, and can therefore trigger real, validly-signed `membership` webhooks for) sends a `membership: added` event whose `team.id` happens to equal the `github_id` of a `Team` already created for a *different* organization Y (e.g. one listed in `Shipit.github_teams`), `Team.find_or_create_by!(github_id: ...)` resolves to Y's existing team row, and `team.add_member(member)` adds the attacker's own `User` (identified purely by `member.login` in the same attacker-controlled payload) to it.

`Team#add_member` performs no organization consistency check either: [4](#0-3) 

The resulting membership is then consumed directly by the authorization gate: [5](#0-4) [6](#0-5) 

So an attacker who is a member/admin of some org (any org configured with a Shipit GitHub App — not necessarily the target org protecting the deploy stacks) can escalate into `Shipit.github_teams` membership for a target org they have no relationship with, and pass `force_github_authentication`, gaining access to stacks, deploys, and rollbacks.

### Impact Explanation
This satisfies the High severity bar defined in scope: "escalation into `Shipit.github_teams` authorization." Once the attacker's `User` is a member of a `Team` whose id is in `Shipit.github_teams`, `current_user.authorized?` returns true, unlocking the entire authenticated surface of the app (stacks, deploys, rollbacks, tasks) for that user, without ever having been invited to, or having any access rights on, the protected organization.

### Likelihood Explanation
The only prerequisite is administering/being a member of *any* organization whose GitHub App is registered with the Shipit instance (multiple orgs are explicitly supported, see `test/dummy/config/secrets_double_github_app.yml`) and being able to trigger (or simply predict/replay) a real `membership` webhook for that org — a normal, unprivileged action within one's own org, requiring no access to the target org, no `webhook_secret` leakage, and no privileged Shipit account. The only "guess" needed is a target team's numeric GitHub `github_id`, which is not a secret and is discoverable via the GitHub API/UI.

### Recommendation
Scope the `Team` lookup/creation in `MembershipHandler#find_or_create_team!` to the organization derived from the verified signature (i.e., require `organization: params.organization.login` in the `find_or_create_by!`/`find_by` clause, matching the record's `organization` column) rather than trusting `github_id` alone across organizations. Additionally, consider validating that `params.organization.login` in the payload matches the organization whose secret was used in `verify_signature`, and enforce a unique index on `(organization, github_id)` for `teams` rather than relying on an unscoped `github_id`.

### Proof of Concept
1. Attacker administers organization `evilcorp`, which has its own GitHub App/webhook configured in Shipit's `secrets.yml` (a normal, supported multi-org setup).
2. Shipit already has a `Team` record for the target org `goodcorp`, e.g. `github_id: 555`, referenced in `Shipit.github_teams` (used to gate access).
3. Attacker triggers (or has GitHub trigger, e.g. by creating/renaming a team in `evilcorp` such that GitHub's `membership` webhook fires) a `membership` event, `action: added`, with body:
```json
{
  "action": "added",
  "team": { "id": 555, "name": "x", "slug": "x", "url": "https://api.github.com/teams/555" },
  "organization": { "login": "evilcorp" },
  "member": { "login": "attacker" }
}
```
This request is signed with `evilcorp`'s legitimate webhook secret, so `verify_signature` passes (`repository_owner` resolves to `evilcorp`, matching the secret used).
4. `WebhooksController#create` dispatches to `MembershipHandler`, which resolves `Team.find_or_create_by!(github_id: 555)` — matching `goodcorp`'s existing team — and calls `team.add_member(User.find_or_create_by_login!("attacker"))`.
5. `attacker`'s `Shipit::User` is now a member of the `goodcorp` team gating `Shipit.github_teams`; after GitHub OAuth login, `current_user.authorized?` returns true and the attacker gains full access to `goodcorp`'s stacks/deploys. [7](#0-6) [8](#0-7)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-29)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-47)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandler < Handler
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
      end
    end
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

**File:** test/controllers/webhooks_controller_test.rb (L129-140)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end
```
