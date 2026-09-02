### Title
Cross-organization webhook forgery via blank `webhook_secret` lets an attacker inject `Membership` rows for teams in `Shipit.github_teams`, escalating `User#authorized?` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook only against the GitHub App config of the *organization named in the payload itself* [1](#0-0) [2](#0-1) , and `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever that organization's `webhook_secret` is blank [3](#0-2) . `MembershipHandler#find_or_create_team!` then looks up/mutates a `Team` purely by `params.team.id`, and `#process` adds the payload's `member.login` to it, with no check that the authenticated organization actually owns that team [4](#0-3) . An attacker who controls a Shipit-configured GitHub organization whose `webhook_secret` is blank can therefore forge a `membership` event naming any existing `Team.github_id` (including one in `Shipit.github_teams`) and any `member.login`, creating a `Membership` row that GitHub never reported.

### Finding Description
Broken binding: `Membership(team_id: T, user: U) exists` should equal `GitHub actually reports U as a member of the team with github_id == T's github_id, as delivered by a webhook GitHub signed for T's real organization`. In practice the code checks a much weaker binding: `verify_webhook_signature(sig, body) == true` where the "organization" used to pick the signing secret is `params.dig('organization','login')` from the **attacker-supplied JSON body**, not derived from `T`'s actual organization [2](#0-1) .

Path:
1. Attacker POSTs to `/webhooks` with header `X-Github-Event: membership` and body `{action:'added', team:{id:<T>, name, slug, url}, organization:{login: attacker_org}, member:{login: attacker_login}}`.
2. `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)`, where `repository_owner` resolves to `attacker_org` (the org the attacker legitimately owns and that is configured in Shipit's multi-org `secrets.github`) [2](#0-1) .
3. Because `attacker_org`'s `webhook_secret` is blank, `verify_webhook_signature` returns `true` regardless of the `X-Hub-Signature` header content or absence [5](#0-4) .
4. `MembershipHandler#process` runs: `find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id)` [6](#0-5) . If `T` already exists (e.g. it is one of `Shipit.github_teams`, provisioned via `oauth.teams` config), the `do |team| ... end` initializer block is skipped entirely, so the record's real `organization`/`slug` is untouched — but the code proceeds to call `team.add_member(User.find_or_create_by_login!(params.member.login))` [7](#0-6) , with no comparison of `team.organization` against `params.organization.login`.
5. `Team#add_member` unconditionally appends the membership [8](#0-7) .
6. `User#authorized?` grants access whenever the user belongs to any team in `Shipit.github_teams` [9](#0-8) , so once the forged `Membership` exists, the attacker's account passes `force_github_authentication`'s authorization gate [10](#0-9) .

None of the listed guards stop this: `drop_unhandled_event` only checks that a handler exists for `membership` events (it does) [11](#0-10) ; the `ExplicitParameters` schema only validates types/presence, not organizational ownership [12](#0-11) ; `verify_signature` ties the check to the attacker's own (correctly-signed-because-secretless) organization, not to the target team's organization.

### Impact Explanation
The attacker gains a forged `Membership` row binding their own (or any chosen) login to a `Team` record whose `id` is used by `Shipit.github_teams`, without GitHub ever reporting that membership. This flips `User#authorized?` to `true` for that login instance-wide, unlocking every controller gated by `force_github_authentication` (stacks, deploys, rollbacks, API client management, etc.) [10](#0-9) . The attack is repeatable for any known/guessable `github_id` of a team in `Shipit.github_teams`, and since the team lookup is by numeric ID only (no per-team organization matching), it is a cross-tenant write — a request the attacker can only legitimately sign for their own organization mutates authorization state tied to a completely different organization's team. This matches "escalation into `Shipit.github_teams` authorization" (High) and, because it lets one org's payload mutate another org's team/authorization data, borders the Critical "payload for one repository mutating another's ... team" category.

### Likelihood Explanation
Preconditions: the attacker must own/control an organization that a Shipit operator has explicitly configured in the multi-org `secrets.github` map (otherwise `Shipit.github(organization:)` raises `GithubOrganizationUnknown` and the request is rejected with 422 before reaching the handler) [13](#0-12) , and that organization's `webhook_secret` must be blank/unset. Given that precondition, the attacker needs only the numeric `github_id` of the target team (discoverable via GitHub's public team/org APIs or prior observation) — no Shipit secret, session, or API token is required, and the request can be sent directly with `curl`/HTTP client without ever touching GitHub. This is a real, low-cost, fully repeatable path once the (plausible, undocumented-as-required) precondition of a secretless org config is met.

### Recommendation
In `MembershipHandler#find_or_create_team!`/`#process`, verify that `params.organization.login` matches the resolved team's known GitHub organization (case-insensitively) before mutating membership, and reject/no-op otherwise. Additionally, `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-77`) should not fail open — treat a missing `webhook_secret` as a hard misconfiguration (raise or reject) rather than "always verified," and `WebhooksController#verify_signature` should also confirm the signed organization actually corresponds to the entities (team/repository) referenced inside the payload.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "forged membership webhook from a secretless org cannot escalate authorization for another org's team" do
  target_team = shipit_teams(:shopify_developers) # in Shipit.github_teams, belongs to 'shopify'
  Shipit.stubs(:github_teams).returns([target_team])
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    Shipit::GitHubApp.new('attacker-org', { app_id: 1, installation_id: 1, webhook_secret: nil })
  )

  @request.headers['X-Github-Event'] = 'membership'
  post :create, as: :json, body: {
    action: 'added',
    team: { id: target_team.github_id, name: target_team.name, slug: target_team.slug, url: target_team.api_url },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker_login' }
  }.to_json

  assert_response :ok
  attacker = Shipit::User.find_by(login: 'attacker_login')
  assert_includes target_team.members.reload, attacker
  assert attacker.authorized?, "attacker gained authorized? via a team it was never actually added to on GitHub"
end
```
Both sides of the equality diverge: no real GitHub delivery ever reported `attacker_login` as a member of `shopify/developers`, yet the `Membership` row and `authorized?` flip to `true` after this single forged POST.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** lib/shipit.rb (L170-181)
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
```
