### Title
Membership webhook mutates pre-existing `Team` records without verifying the authenticating organization matches the team's owning org - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects a GitHub App purely from attacker-controlled `organization.login` (or `repository.owner.login`) and accepts the webhook as "verified" whenever that org's `webhook_secret` is blank [1](#0-0) [2](#0-1) . `Shipit::Webhooks::Handlers::MembershipHandler#find_or_create_team!` then looks up the `Team` purely by the attacker-supplied numeric `team.id`, and only sets `team.organization` on first creation — on every subsequent call it silently reuses whichever `Team` row already has that `github_id`, regardless of whether `params.organization.login` matches the team's real `organization` [3](#0-2) .

### Finding Description
Binding claimed broken: `organization whose webhook_secret verified this request == organization that owns the Team row being mutated`.

- `WebhooksController#repository_owner` returns `params.dig('organization', 'login')` when there is no `repository` key, which is always true for `membership` events [4](#0-3) .
- `verify_signature` calls `Shipit.github(organization: repository_owner)` to pick the `GitHubApp` used to check the signature [1](#0-0) .
- `GitHubApp#verify_webhook_signature` unconditionally returns `true` if that org's `webhook_secret` is blank: `return true unless webhook_secret` [2](#0-1) . Per `docs/setup.md`'s multi-org example and the example secrets files, `webhook_secret` is explicitly allowed to be left `nil` per-org [5](#0-4) .
- `Shipit::Webhooks.for_event('membership')` dispatches unconditionally to `MembershipHandler#process` [6](#0-5) .
- `MembershipHandler#find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` — the block only executes when the record is *created*; if a `Team` with that `github_id` already exists (e.g. one of the teams gating access, populated via `Shipit.github_teams`/`Team.find_or_create_by_handle`), the existing record is returned untouched, and its `organization` is never re-checked against the request's `organization.login` [7](#0-6) .
- `process` then unconditionally does `team.add_member(member)` for `action == 'added'`, appending the attacker-named `member.login` (auto-vivified via `User.find_or_create_by_login!`) to that team's `members` [8](#0-7) .

Consequently, an attacker who can freely forge a webhook for *any* org whose `webhook_secret` is unset can name a `team.id` belonging to a different, properly secured org — and the handler applies the membership mutation to that existing team without ever validating provenance. This directly matters for authorization: `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [9](#0-8) , and `Shipit.github_teams` is exactly the set of `Team` records referenced by `oauth.teams` config [10](#0-9) . If the attacker can discover/guess the `github_id` of one of those gating teams, they can add an arbitrary Shipit `User` (identified only by `login`, with no proof of GitHub identity) to it, and that user becomes `authorized?` and passes `force_github_authentication` for the whole multi-tenant Shipit instance [11](#0-10) .

Existing guards that fail to stop this: `verify_signature`'s org-scoped signature check is bypassed entirely by design when `webhook_secret` is blank; `drop_unhandled_event` does not apply (membership has a handler); the `ExplicitParameters` schema on `MembershipHandler` only validates types/presence, not organization consistency [12](#0-11) ; and no model validation on `Team` enforces that `organization` cannot diverge from an update-triggering webhook (the unique index is only `["organization","slug"]`, not `github_id` cross-checked against org).

### Impact Explanation
An attacker who controls (or exploits) any org key configured in `secrets.yml` without a `webhook_secret` can, with unauthenticated POST requests to `/webhooks`, mutate `Team` membership belonging to a completely different, properly-secured organization, by referencing its known/guessed `github_id`. Because Shipit authorization (`User#authorized?`) is gated by team membership, this is an escalation into `Shipit.github_teams` authorization — a cross-tenant authentication/authorization bypass affecting every stack/repository the Shipit instance manages, not just one repository. This matches the "High - escalation into `Shipit.github_teams` authorization" impact category. It is fully repeatable: each POST can add/remove members from any team whose `github_id` is known, for as long as the misconfigured org key with a blank `webhook_secret` remains.

### Likelihood Explanation
Requires the documented (and explicitly supported) multi-org config with at least one org key lacking a `webhook_secret`, which the app's own example secrets files show as a legitimate configuration option [5](#0-4) [13](#0-12) . The attacker also needs to know/guess a target team's numeric GitHub team `id` (discoverable via GitHub's public/team APIs or by observing prior webhook traffic). No Shipit credentials, sessions, or GitHub tokens are required — only network access to the `/webhooks` endpoint. Cost is a single crafted HTTP POST; the attack is trivially repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify `params.organization.login` against the existing `team.organization` before mutating membership, and reject/no-op (or raise) on mismatch rather than silently reusing the row. More fundamentally, `WebhooksController#verify_signature` should not treat a blank `webhook_secret` as automatically "verified" for organizations that are not explicitly opted into unsigned webhooks, and the resolved `github_app`'s organization should be threaded into the handler and checked against every team/record it mutates.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb` style, not asserting it belongs there but describing the scenario):
1. Configure two orgs in `Shipit.secrets.github`: `"secured-org"` with a real `webhook_secret`, and `"open-org"` with `webhook_secret` blank/nil.
2. Seed a `Team` fixture with `organization: "secured-org"`, `github_id: 999`, included in `Shipit.github_teams` (stub `Shipit.stubs(:github_teams).returns([that_team])`).
3. POST to `/webhooks` with header `X-Github-Event: membership`, **no** `X-Hub-Signature` header, and body:
   ```json
   { "action": "added",
     "team": { "id": 999, "name": "Secured", "slug": "secured", "url": "https://example.com" },
     "organization": { "login": "open-org" },
     "member": { "login": "attacker" } }
   ```
4. Assert `response.status == 200` (not 422), i.e., `verify_signature` passed with no signature because `open-org`'s `webhook_secret` is blank.
5. Assert `Team.find_by(github_id: 999).organization == "secured-org"` (unchanged — proving the *pre-existing* team is the one mutated, not a new `open-org` team) and `assert_difference -> { Membership.count }, 1` — the attacker's `member.login: "attacker"` User was added to the `secured-org` team's members.
6. Assert `User.find_by(login: "attacker").authorized?` is now `true` given the stubbed `Shipit.github_teams`, demonstrating the authorization escalation.

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

**File:** app/models/shipit/webhooks.rb (L19-21)
```ruby
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
