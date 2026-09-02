### Title
Blank `webhook_secret` for an org lets any unauthenticated attacker forge `membership` webhooks and escalate into `Shipit.github_teams` authorization - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the signing org purely from attacker-controlled payload fields and defers trust entirely to `GitHubApp#verify_webhook_signature`, which returns `true` unconditionally when `webhook_secret` is blank for that org. Combined with `MembershipHandler#find_or_create_team!`, which trusts `organization.login`/`team.id`/`member.login` from the same unverified body, an attacker can add an arbitrary GitHub login (their own account) to any `Team` record, and if that team's `github_id` is one of the IDs in `Shipit.github_teams`, `User#authorized?` grants that attacker full application access after they log in normally via OAuth.

### Finding Description
The binding assumed by the code is: **the organization whose `webhook_secret` cryptographically validated the request body == the organization whose team/membership state is mutated by the handler**. In `verify_signature`, the signing org is derived from the payload itself: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` when the target org's `webhook_secret` is not configured: [3](#0-2) 

If `Shipit.github(organization: 'shopify').webhook_secret` is blank (a plausible operational misconfiguration, e.g. only one org fully configured in a multi-org install, or the secret omitted during setup), any request claiming to be for `shopify` passes verification with **no cryptographic check whatsoever** — the `X-Hub-Signature` header content is irrelevant.

`MembershipHandler#process`/`#find_or_create_team!` then trusts the same unverified body to create/find a `Team` and add an arbitrary `member.login` to it: [4](#0-3) 

If the attacker targets a `team.id` matching an existing `Team` whose `github_id` is one of `Shipit.github_teams` (the configured authorization teams), the created `Membership` directly satisfies: [5](#0-4) 

which is consumed by `force_github_authentication`: [6](#0-5) 

Attacker's exact request: `POST /webhooks` with header `X-Github-Event: membership` and body `{action: "added", team: {id: <id of a Shipit.github_teams team>, name, slug, url}, organization: {login: "shopify"}, member: {login: "<attacker's real GitHub login>"}}` — no valid `X-Hub-Signature` needed since verification is bypassed unconditionally. The attacker then logs in through the normal OAuth flow with their real GitHub account (login matching `member.login`); `current_user` resolves to the `User` row created by the forged webhook, and `authorized?` now returns `true`, granting them full access to stacks, deploys, and secrets.

Existing guards fail because: `drop_unhandled_event` only screens by event name, `ExplicitParameters` schema in `MembershipHandler` only checks field *types/presence*, not provenance, and `verify_signature` performs no cross-check between which org's secret validated the payload and what the payload subsequently claims to mutate — under the blank-secret precondition, no org actually authenticates anything.

### Impact Explanation
Once exploited, an unprivileged attacker gains: (1) an arbitrary `Membership` row linking their own real GitHub account to a `Team`, and (2) if that team is among `Shipit.github_teams`, full authenticated access to the Shipit instance (stack management, deploys, rollbacks, secrets) — this matches the listed High-severity category "escalation into `Shipit.github_teams` authorization." The attack is repeatable for any team `github_id`/`organization.login` combination and is not scoped to one repository — it compromises the entire tenant's access control model.

### Likelihood Explanation
The attack requires zero attacker-held secrets and zero privileges — only that the operator has left `webhook_secret` blank for the org in `secrets.yml` (`github.webhook_secret`), which is an explicit, documented but optional setting: [7](#0-6) 

This is a real, reachable misconfiguration (not a theoretical one) since the setup docs describe it as something operators must "copy" in, implying it can be omitted. Given that precondition, the attacker cost is a single HTTP POST plus a normal OAuth login with their own account — fully repeatable and requires no live GitHub interaction to demonstrate.

### Recommendation
Do not permit unconditional trust when `webhook_secret` is unset. Instead, `GitHubApp#verify_webhook_signature` should fail closed (return `false`/raise) if no `webhook_secret` is configured, or the application should refuse to boot/serve webhooks for orgs lacking a configured secret. Additionally, `MembershipHandler` should verify that `params.organization.login` matches the org actually used to authenticate the request (`repository_owner`) rather than trusting it independently.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual, no live GitHub)
test ":membership forges attacker into an authorized team when webhook_secret is blank" do
  authorized_team = shipit_teams(:shopify_developers)
  Shipit.stubs(:github_teams).returns([authorized_team])

  blank_secret_app = Shipit::GitHubApp.new('shopify', { webhook_secret: nil })
  Shipit.stubs(:github).with(organization: 'shopify').returns(blank_secret_app)
  Shipit.stubs(:github).returns(blank_secret_app)

  @request.headers['X-Github-Event'] = 'membership'
  @request.headers['X-Hub-Signature'] = 'sha1=not-a-real-signature'

  body = {
    action: 'added',
    team: { id: authorized_team.github_id, name: authorized_team.name, slug: authorized_team.slug, url: authorized_team.api_url },
    organization: { login: 'shopify' },
    member: { login: 'attacker' }
  }.to_json

  assert_difference -> { Membership.count }, 1 do
    post :create, body:, as: :json
    assert_response :ok
  end

  attacker = User.find_by(login: 'attacker')
  assert authorized_team.members.include?(attacker)
  assert attacker.authorized?, "attacker should NOT be authorized without a verified signature"
end
```
Both sides of the binding: before exploit, `authorized?` for a random login should be `false` because no org verified the request; after the forged POST, `authorized?` becomes `true` — demonstrating the broken provenance binding.

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

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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
