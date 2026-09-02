Confirmed: the vulnerability is real and exactly as described.

The binding claimed to be broken: `organization_that_verified_signature == organization_owning_the_Team_row_mutated`. Tracing `WebhooksController#verify_signature` [1](#0-0)  shows it selects the `GitHubApp` (and thus `webhook_secret`) using `repository_owner`, which is read from `params.dig('repository','owner','login')` or `params.dig('organization','login')` [2](#0-1) . Since the attacker owns that organization, they legitimately possess its `webhook_secret` and can produce a valid `X-Hub-Signature` per `GitHubApp#verify_webhook_signature` [3](#0-2) .

Once past signature verification, `MembershipHandler#find_or_create_team!` looks up the `Team` solely by `github_id`, with no check that `params.organization.login` matches the team's stored `organization` column: `Team.find_or_create_by!(github_id: params.team.id) do |team| ... end` [4](#0-3) . When the Team already exists (e.g. prefetched via `teams:fetch`), the block is skipped entirely, so the `organization` column is never re-validated against the verified organization. `process` then does `team.add_member(User.find_or_create_by_login!(params.member.login))` [5](#0-4) , creating a `Membership` for the attacker's own login on the victim org's `Team`.

This directly feeds `User#authorized?`, which checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) , gating access in `Authentication#force_github_authentication` [7](#0-6) . So an attacker who owns any GitHub org configured in Shipit's multi-org `github:` secrets config, and who knows/guesses the `github_id` of a `Team` in `Shipit.github_teams` belonging to a *different* org, can self-grant `authorized?` on the whole Shipit instance — no existing guard (`verify_signature`, `ExplicitParameters` schema, or the handler) checks that `params.organization.login` matches the `Team#organization` of the record being mutated.

### Title
Cross-organization Team membership forgery via webhook signature/organization mismatch in `MembershipHandler#find_or_create_team!` - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController` verifies the webhook signature using the `webhook_secret` of whichever organization is named in the payload's `repository.owner.login`/`organization.login`, but `MembershipHandler#find_or_create_team!` looks up an existing `Team` purely by numeric `github_id`, never re-checking that the verified organization matches the `Team#organization` of the record it mutates. An attacker who controls a distinct GitHub organization configured in Shipit can forge a signature-valid `membership` webhook that adds themselves to any pre-existing `Team` belonging to another organization by supplying that team's `github_id`.

### Finding Description
Binding claimed and broken: `org_that_signed_the_webhook (repository_owner from payload) == org_owning_the_Team_row_mutated (Team#organization)`.

Path: `WebhooksController#create` → `verify_signature` selects `Shipit.github(organization: repository_owner)` and validates HMAC against that org's `webhook_secret` [1](#0-0)  — `repository_owner` is attacker-controlled payload data [2](#0-1) . It then dispatches to `MembershipHandler.call(params)` [8](#0-7) , whose `process` calls `find_or_create_team!`, which resolves `Team` by `github_id` alone: `Team.find_or_create_by!(github_id: params.team.id) do |team| ... end` [4](#0-3) . When a `Team` with that `github_id` already exists (e.g., from `bin/rake teams:fetch`), the create-block (which would set `team.organization = params.organization.login`) never runs, so the returned `Team` is the pre-existing one belonging to whatever org it was originally created under — independent of which org's secret signed this request. `process` then unconditionally does `team.add_member(User.find_or_create_by_login!(params.member.login))` [9](#0-8) , using `params.member.login`, which is also attacker-controlled and unrelated to the signing org.

No existing guard prevents this: `drop_unhandled_event` only checks the event exists a handler; the `ExplicitParameters` schema for `MembershipHandler` only enforces types/presence, not organization consistency [10](#0-9) ; `verify_signature` authenticates the *request* against the org named in the payload but never re-validates that same org against the specific `Team` record being touched.

### Impact Explanation
The attacker gains an unauthorized `Membership` row linking their own GitHub login to a `Team` in `Shipit.github_teams` belonging to a victim organization they do not control. This directly satisfies `User#authorized?`'s `teams.where(id: Shipit.github_teams.map(&:id)).exists?` check [6](#0-5) , which gates access to the entire Shipit instance in `force_github_authentication` [7](#0-6) . This is a High-severity escalation into `Shipit.github_teams` authorization, repeatable for any pre-existing `Team` github_id the attacker can enumerate/guess, across any org configured under this shared Shipit instance in a multi-org setup.

### Likelihood Explanation
Requires: (1) Shipit configured with multiple GitHub orgs/apps (documented multi-org setup) where the attacker controls one org's app/webhook_secret, or more simply, any org whose webhook_secret an "attacker" org possesses because they were legitimately onboarded; (2) the target `Team` row already exists with a known `github_id` (predictable/enumerable, e.g., sequential GitHub team IDs, or discoverable via other means); (3) the target org is listed in `Shipit.github_teams`. This is a realistic configuration per `docs/setup.md`'s "Using Multiple GitHub Applications" section. Attacker cost is low — one crafted HTTP POST, fully repeatable/scriptable.

### Recommendation
In `find_or_create_team!`, always verify that the resolved `Team#organization` matches `params.organization.login` (which is itself validated to equal `repository_owner`, i.e. the org whose secret signed the request) before proceeding; raise/reject on mismatch rather than silently reusing a differently-owned `Team` record. Additionally consider composing the lookup key on `[github_id, organization]` rather than `github_id` alone.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`-style, no live GitHub):
1. Fixture: a `Team` `victim_team` with `organization: 'victim-org'`, `github_id: 999`, in `Shipit.github_teams`.
2. Configure `Shipit.stubs(:github_teams).returns([victim_team])`.
3. Stub `Shipit.github(organization: 'attacker-org').verify_webhook_signature` to return `true` (simulating attacker knows their own org's secret) — do NOT stub anything for `victim-org`.
4. POST `/webhooks` with header `X-Github-Event: membership`, body: `{ action: 'added', team: { id: 999, name: 'x', slug: 'x', url: 'x' }, organization: { login: 'attacker-org' }, member: { login: 'attacker' }, repository: { owner: { login: 'attacker-org' } } }`.
5. Assert response is `:ok` and `Membership.exists?(team_id: victim_team.id, user: User.find_by(login: 'attacker'))`.
6. Assert `User.find_by(login: 'attacker').authorized?` is `true`.
7. Both assertions passing demonstrate the binding `org signing request == org owning mutated Team` does not hold, confirming the vulnerability.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-33)
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

**File:** app/models/shipit/webhooks.rb (L20-20)
```ruby
          'membership' => [Handlers::MembershipHandler],
```
