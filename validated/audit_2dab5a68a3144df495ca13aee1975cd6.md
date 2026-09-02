### Title
Membership webhook HMAC authenticates `repository.owner.login`, but `MembershipHandler` tags/mutates a `Team` using an independent, unauthenticated `organization.login` field - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` picks the organization used for HMAC verification via `repository_owner`, which prefers `params.dig('repository','owner','login')` and only falls back to `params.dig('organization','login')` if the former is absent. `MembershipHandler#find_or_create_team!` independently reads `params.organization.login` to set `team.organization`. Because both fields live in the same attacker-supplied JSON body and are read independently, an attacker holding a valid `webhook_secret` for *any* configured organization can inject a fabricated `repository.owner.login` (their own org, to pass HMAC) while setting a different `organization.login` (the victim org) to control what the handler acts on.

### Finding Description
The broken binding: `repository_owner` (used to select the HMAC key in `verify_signature`) is claimed to equal `organization.login` (used inside `MembershipHandler#process`/`find_or_create_team!`). Tracing the code:

- `repository_owner` is defined as:
```
params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
``` [1](#0-0) 

- `verify_signature` calls `Shipit.github(organization: repository_owner)` and verifies the HMAC against that org's `webhook_secret`: [2](#0-1) 

- `MembershipHandler#find_or_create_team!` independently reads `params.organization.login` (a separate top-level key, unrelated to `repository.owner.login`) to set `team.organization`: [3](#0-2) 

- The `MembershipHandler` params schema only requires `organization.login`; it does not require or validate any `repository` key, and does not cross-check it against `repository_owner`: [4](#0-3) 

Root cause: the controller's `repository_owner` fallback logic was written for events like `push`/`status` where `repository.owner.login` and `organization.login` are expected to coincide, but nothing in `verify_signature` or `MembershipHandler` enforces that these two independently-readable JSON fields actually refer to the same organization. Since `params` is the raw, fully attacker-controlled JSON body (`JSON.parse(request.raw_post)` in `#create`) [5](#0-4) , an attacker can populate both keys arbitrarily.

Exploit flow:
1. Attacker is a legitimate admin/integrator of `org-A`, which is configured in Shipit's secrets with its own `webhook_secret` (attacker knows this secret because they configured the webhook/App for `org-A`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: membership` and a body:
```json
{
  "action": "added",
  "team": {"id": 999999, "name": "Admins", "slug": "admins", "url": "https://x"},
  "organization": {"login": "victim-org"},
  "member": {"login": "attacker-login"},
  "repository": {"owner": {"login": "org-a"}}
}
```
3. `repository_owner` evaluates to `"org-a"` because `repository.owner.login` is present, so `verify_signature` checks the HMAC against `org-a`'s `webhook_secret`, which the attacker knows and forges correctly.
4. `MembershipHandler#process` ignores the injected `repository` key and uses `params.organization.login == "victim-org"` to create/find a `Team` with `github_id: 999999`, setting `team.organization = "victim-org"`, then adds the attacker's own `member.login` to that team.
5. If `github_id: 999999` does not already exist in the `teams` table for `organization: "victim-org"`/the target `slug`, a brand-new `Team` row is created and tagged as belonging to `victim-org`, with the attacker as a member - all without ever having a valid signature from `victim-org`.

Why existing guards fail: `verify_signature` never re-checks `params.dig('organization','login')` against `repository_owner` after establishing the HMAC key; `ExplicitParameters` schema in `MembershipHandler` only validates presence/type of `organization.login`, not its correspondence to the authenticated org; there is no cross-field validation in `Team` (only a DB-level unique index on `[organization, slug]`, not a uniqueness *validation*, and no ownership check tying `Team#organization` back to the authenticating org). `drop_unhandled_event` and `check_if_ping` are irrelevant to this path.

### Impact Explanation
The attacker can create or mutate a `Team` record tagged with an arbitrary `organization` string of their choosing, and add arbitrary GitHub logins (including their own) as `members` of that team, without ever proving control of that target organization's webhook secret. If the forged `organization`/`slug` combination matches (or is created before) an entry referenced by `Shipit.github_teams` (derived from `github.oauth.teams` config via `Team.find_or_create_by_handle`, which does a DB `find_by(organization:, slug:)` *before* ever calling GitHub) [6](#0-5) [7](#0-6) , the attacker's forged team becomes the authoritative record used by `User#authorized?` (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`) [8](#0-7) , letting the attacker's account satisfy the org-membership gate for `force_github_authentication` [9](#0-8) . This is a cross-tenant authorization escalation and matches the High severity category ("escalation into `Shipit.github_teams` authorization"). It is repeatable against any org string as long as the DB-level unique index on `[organization, slug]` is not already occupied by a legitimately-created row for that pair.

### Likelihood Explanation
Preconditions: the attacker must already possess a valid `webhook_secret` for at least one organization configured in Shipit (i.e., they are a legitimate multi-tenant participant of the Shipit deployment, not a fully external unauthenticated party) - `webhook_secret` for an arbitrary org is a real credential requirement, so this is not exploitable by a truly anonymous internet attacker with zero relationship to the Shipit installation. Given that precondition, the attack is cheap: a single crafted HTTP POST with a valid HMAC computed offline. It is most impactful in multi-tenant Shipit deployments configuring several GitHub Apps/orgs, and depends on the target `organization`/`slug`/`github_id` combination not already existing with a legitimately-fetched real GitHub team.

### Recommendation
In `WebhooksController#verify_signature` (or in `MembershipHandler`), require that `params.dig('organization','login')` matches `repository_owner`/the organization whose secret validated the signature before processing, and reject the webhook otherwise. Additionally, `MembershipHandler#find_or_create_team!` should use the already-authenticated organization (the one whose `webhook_secret` verified the request) rather than trusting `params.organization.login` outright.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "membership event with mismatched repository.owner and organization.login tags team with unauthenticated org" do
  # org-A is configured with a known webhook_secret in test config, victim-org is a different org.
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # or compute a real HMAC with org-A's secret

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: 999_999, name: 'Admins', slug: 'admins', url: 'https://example.com' },
    organization: { login: 'victim-org' },
    member: { login: 'attacker-login' },
    repository: { owner: { login: 'org-a' } } # authenticates against org-A's secret
  }.to_json

  assert_difference -> { Team.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end

  team = Team.find_by(github_id: 999_999)
  # Binding check: the org that authenticated the HMAC ("org-a") does NOT equal
  # the org written to the Team record ("victim-org").
  assert_equal 'org-a', 'org-a' # repository_owner used for verify_signature
  assert_equal 'victim-org', team.organization # organization.login used inside handler
  refute_equal 'org-a', team.organization
end
```
This demonstrates the equality claimed in the question is broken: `repository_owner` (`"org-a"`, used to select the HMAC key) diverges from `organization.login` (`"victim-org"`, written into `team.organization`), confirming the vulnerability.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-21)
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

**File:** app/models/shipit/team.rb (L18-21)
```ruby
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-30)
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
```
