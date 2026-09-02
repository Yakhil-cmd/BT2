### Title
Forged `membership` webhook from any unsecured-org's GitHub App config bypasses `Shipit.github_teams` authorization via organization-blind team lookup - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::MembershipHandler#find_or_create_team!` looks up the target `Team` solely by `params.team.id` (`github_id`), never validating that `params.organization.login` matches the team's actual owning organization. Combined with `GitHubApp#verify_webhook_signature` returning `true` whenever an org's `webhook_secret` is blank, a webhook accepted for *any* configured (even attacker-controlled) organization can add an arbitrary GitHub login to a `Team` that belongs to a completely different organization — including one referenced by `Shipit.github_teams` — producing a full authorization bypass.

### Finding Description
The broken binding is: `params.organization.login == team.organization` must hold before `team.add_member(member)` executes, matching GitHub's own org/team scoping semantics. It does not.

Path:
1. `Shipit::WebhooksController#verify_signature` selects the GitHub App config purely from the attacker-controlled payload: `Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('organization', 'login')` [1](#0-0) [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank for that org's config entry: `return true unless webhook_secret` [3](#0-2) . In a multi-org `secrets.github` block, this is per-organization, so any one org entry that omits `webhook_secret` (documented as optional) turns off signature verification for payloads claiming that organization.
3. `MembershipHandler#find_or_create_team!` resolves the `Team` by `github_id` alone: `Team.find_or_create_by!(github_id: params.team.id) { |team| team.github_team = params.team; team.organization = params.organization.login }` [4](#0-3) . The block only runs on creation; if a `Team` row with that `github_id` already exists (e.g., a legitimate team already tracked because it's in `Shipit.github_teams`), the lookup returns that existing record regardless of the `organization.login` claimed in the forged payload.
4. `process` then unconditionally does `team.add_member(member)` for `action == 'added'`, where `member` is created/found purely from `params.member.login` — again attacker-supplied [5](#0-4) .
5. `Shipit.github_teams` builds the authorization set from `Team` AR records (`github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }`) [6](#0-5) , and `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) . Since the attacker's forged membership targets the same `Team` row (matched by `github_id`), the attacker's `User` record — created via the forged `member.login` and later logged into by the same attacker through normal OAuth — passes `authorized?` and thus `force_github_authentication` [8](#0-7) .

Existing guards fail here because: `drop_unhandled_event`/`ExplicitParameters` only validate shape, not provenance-to-team binding; `verify_signature` authenticates "this payload came from *an* org configured in secrets.github with no secret," not "this payload's team/organization actually belongs together"; and `find_or_create_team!` never re-checks `organization` against an existing team's stored `organization` column.

### Impact Explanation
A successful forgery lets an attacker join any pre-existing `Team` tracked by Shipit — including one enumerated in `Shipit.github_teams` — without any real GitHub team membership. After a normal OAuth login (which only needs an attacker-owned GitHub account, no special grant), the attacker's `User#authorized?` becomes `true`, granting full access to every controller gated by `force_github_authentication`, i.e., stack/task/deploy access across all repositories managed by that Shipit instance. This is repeatable for any `github_id` the attacker can enumerate/guess, and is not confined to the attacker's own org/repository — it is a cross-tenant authorization bypass, matching the "authentication bypass (forged webhook ... accepted)" Critical category.

### Likelihood Explanation
The chain requires: (a) the Shipit operator running a multi-org `secrets.github` config, (b) at least one entry in that config (not necessarily the legitimate org itself) lacking `webhook_secret` — a documented-optional field, and (c) the attacker knowing/guessing the numeric `github_id` of a `Team` already tracked in Shipit's database (visible in `Shipit.github_teams`, and GitHub team ids are sequential/discoverable via the GitHub API in many cases). Given these operator-side conditions, attacker cost is a single unauthenticated HTTP POST plus a normal OAuth login — no secrets of Shipit's are needed. The precondition (operator onboarding an untrusted org into `secrets.github` without a webhook secret) is an unusual but explicitly-permitted configuration per this codebase's own `verify_webhook_signature` logic.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` AND `organization` (e.g., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and reject/log-and-drop the event if an existing team's stored `organization` doesn't match `params.organization.login`. Additionally, consider making `webhook_secret` mandatory (fail closed) for any organization entry in a multi-org `secrets.github` config rather than silently trusting unsigned payloads.

### Proof of Concept
Minitest plan (webhooks controller / integration test, no live GitHub):
1. Fixture: an existing `Team` (e.g., `shipit_teams(:shopify_developers)`, `github_id: X`, `organization: 'shopify'`) already included in `Shipit.stubs(:github_teams).returns([shipit_teams(:shopify_developers)])`.
2. Stub `Shipit.github(organization: 'evilcorp')` to return a `GitHubApp` built with a config hash that has no `webhook_secret` (simulating the attacker-onboarded org), so `verify_webhook_signature` returns `true` for any body/signature.
3. POST to `/webhooks` with header `X-Github-Event: membership`, body: `{ action: 'added', team: { id: X, name: 'Developers', slug: 'developers', url: '...' }, organization: { login: 'evilcorp' }, member: { login: 'attacker' } }`, no `X-Hub-Signature` header.
4. Assert `response.status == 200` and `Team.find_by(github_id: X).members.map(&:login)` includes `'attacker'` — i.e., `team.organization` stays `'shopify'` while membership was mutated from a payload claiming `'evilcorp'`, proving `params.organization.login == team.organization` is not enforced.
5. Follow-up controller test: `session[:user_id] = User.find_by(login: 'attacker').id`; `get :index` (e.g., `StacksController`); assert `response.status == 200` instead of `:forbidden`, proving `current_user.authorized?` now returns `true` solely due to the forged webhook.

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
