### Title
`MembershipHandler#find_or_create_team!` writes `Team.organization` from `params.organization.login` while `WebhooksController#verify_signature` authenticates against `params.repository.owner.login` when present — ([File: app/models/shipit/webhooks/handlers/membership_handler.rb], [File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#repository_owner` picks `params.dig('repository','owner','login')` first, falling back to `params.dig('organization','login')` only if `repository` is absent. `MembershipHandler#find_or_create_team!` unconditionally uses `params.organization.login` to set `Team#organization`, regardless of which field authenticated the request. An attacker who owns a real GitHub App/webhook for their own org can craft a raw membership payload containing both a `repository.owner.login` (their own org, used only for signature verification) and a divergent `organization.login` (an arbitrary string, e.g. `shopify`), causing a `Team` row to be created whose `organization` does not match the org that actually signed the request.

### Finding Description
Binding claimed: `Team.organization` (written in `find_or_create_team!`) `==` `repository_owner` (the org actually authenticated by `verify_signature`).

Code path:
- `app/controllers/shipit/webhooks_controller.rb:59-62` — `repository_owner` reads `params.dig('repository','owner','login') || params.dig('organization','login')` from the raw JSON body (Rails' parsed `params`, same body the attacker fully controls) [1](#0-0) .
- `verify_signature` (lines 24-38) uses `repository_owner` solely to pick which `GitHubApp`/`webhook_secret` to check the signature against [2](#0-1) .
- `MembershipHandler#find_or_create_team!` always uses `params.organization.login` (a *different* field of the same payload) to set `team.organization`, never consulting `repository_owner`/`repository.owner.login` [3](#0-2) .
- The `MembershipHandler` schema (`params do ... end`) declares only `action`, `team`, `organization`, `member` — it does not declare or forbid a `repository` key, and `ExplicitParameters` (as used by every handler, e.g. `PushHandler`, which only declares `ref`/`after` while real GitHub push payloads carry dozens of extra fields such as `repository`) silently ignores undeclared top-level keys rather than rejecting the payload [4](#0-3) .

Exploit request: attacker owns `attacker-org`'s GitHub App/webhook secret. They POST to `/webhooks` with header `X-Github-Event: membership`, HMAC-signed with `attacker-org`'s `webhook_secret`, and a JSON body:
```json
{
  "action": "added",
  "team": { "id": <fresh integer>, "name": "x", "slug": "ops", "url": "http://x" },
  "organization": { "login": "shopify" },
  "member": { "login": "<any real github login>" },
  "repository": { "owner": { "login": "attacker-org" } }
}
```
`repository_owner` resolves to `"attacker-org"` (because `repository.owner.login` is present and takes precedence), so `verify_signature` checks the signature against `attacker-org`'s own secret — which the attacker controls and thus always passes. `MembershipHandler` then runs `Team.find_or_create_by!(github_id: <fresh id>) { |team| team.organization = params.organization.login }`, writing `team.organization = "shopify"`, a value entirely disconnected from the authenticated `"attacker-org"`.

Why existing guards fail: `drop_unhandled_event` only checks the event name is handled; `ExplicitParameters` schema for `MembershipHandler` does not require or validate consistency between `organization.login` and `repository.owner.login`; there is no model validation on `Team#organization` tying it to the verified `repository_owner`.

### Impact Explanation
Downstream, `Shipit.github_teams` (`lib/shipit.rb:256-258`) iterates the configured `github.oauth.teams` handles and calls `Team.find_or_create_by_handle(handle)`, which downcases the handle and does `find_by(organization:, slug:)` before ever hitting the GitHub API [5](#0-4) . If the attacker sets `organization.login` to the exact-case string matching the downcased configured organization (e.g. `"shopify"`, matching config entry `"shopify/ops"`) and `team.slug` to `"ops"`, their forged `Team` row is returned by `find_or_create_by_handle` in place of the legitimate GitHub-backed team, complete with whatever member (`params.member.login`) the attacker added via `team.add_member(member)` in `MembershipHandler#process` [6](#0-5) . `User#authorized?` grants access based on `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) , so any GitHub login the attacker names becomes a member of the "privileged" team and gains Shipit login access — an authentication/authorization bypass reaching a different tenant's (`shopify`'s) team semantics, from a webhook the attacker fully controls for `attacker-org`. This matches the "escalation into `Shipit.github_teams` authorization" High-severity category, with a plausible escalation into cross-tenant `Team` row provenance mismatch (Critical-adjacent) since a row purporting to belong to `shopify` is created and populated entirely by `attacker-org`'s credentials.

Note: exploitation requires the attacker to guess/know the exact-case organization/slug string configured in `Shipit.github_teams` (e.g. from `docs`/public knowledge of the target's oauth.teams config); it does **not** rely on case-insensitive matching as the question's proof idea suggested — `find_or_create_by_handle` only downcases the *lookup* handle, not the already-stored `organization` column, so a mixed-case spoof like `"Shopify"` would **not** match a lowercase-configured `"shopify/ops"`. The attacker must supply the exact lowercase string to succeed, which is trivial since they control the payload.

### Likelihood Explanation
Preconditions: attacker needs a legitimate GitHub App/webhook installed on any org they control (`attacker-org`), which is available to any GitHub user for free; they need to know the target's configured `Shipit.github_teams` handle (organization/slug), which is often documented or guessable (e.g. `"shopify/ops"`, `"shopify/developers"`); they need a fresh `team.id` integer (trivially satisfied — any never-seen integer). No Shipit session, API token, or victim secret is required — only the attacker's own webhook secret, which they legitimately possess. This is fully repeatable and scriptable against arbitrary target organizations by varying `organization.login`.

### Recommendation
In `find_or_create_team!`, derive `team.organization` from the authenticated `repository_owner` (the same value `WebhooksController#verify_signature` used), not from `params.organization.login` directly — e.g. pass the verified organization into the handler and use it, or add a schema check that rejects the payload if `repository.owner.login` (when present) differs from `organization.login`. More broadly, `WebhooksController#repository_owner` should not allow a `repository.owner.login`/`organization.login` mismatch to silently pick different values used by different downstream consumers of the same payload — validate that they agree when both are present.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test ":membership with mismatched repository.owner and organization.login stores the spoofed organization" do
  @request.headers['X-Github-Event'] = 'membership'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # signature verified against attacker-org's own secret in real life

  attacker_authenticated_org = 'attacker-org'
  spoofed_org = 'shopify'

  body = {
    action: 'added',
    team: { id: 999_999, name: 'Ops', slug: 'ops', url: 'http://example.com' },
    organization: { login: spoofed_org },
    member: { login: 'walrus' },
    repository: { owner: { login: attacker_authenticated_org } } # this is what verify_signature actually authenticates
  }.to_json

  assert_difference -> { Team.count }, 1 do
    post :create, body:, as: :json
    assert_response :ok
  end

  team = Team.find_by(github_id: 999_999)
  # BROKEN BINDING: Team.organization should equal the authenticated org (attacker_authenticated_org),
  # but instead equals the attacker-supplied, unauthenticated organization.login field.
  refute_equal attacker_authenticated_org, team.organization
  assert_equal spoofed_org, team.organization
end
```
This demonstrates `Team.organization` ("shopify") diverging from the organization whose secret actually signed the request ("attacker-org"), confirming the broken binding without requiring live GitHub access.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-11)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

```

**File:** app/models/shipit/team.rb (L17-21)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
