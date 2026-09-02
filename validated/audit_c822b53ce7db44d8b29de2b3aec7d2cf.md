### Title
Cross-organization webhook forges membership in another org's `Team`, enabling authorization escalation via `Team.find_or_create_by!(github_id:)` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` looks up `Team` solely by `github_id: params.team.id`, with no check that `params.organization.login` (the org whose `webhook_secret` was used to authenticate the request) actually owns that `github_id`. An attacker who genuinely controls a GitHub App installation on their own org (and thus its real `webhook_secret`) can forge a signed `membership` webhook naming their own org but embedding another org's team's `github_id`, causing their own GitHub user to be added as a member of that other team.

### Finding Description
The broken binding, stated as an equality that the code assumes but never checks:

`params.organization.login (the org whose webhook_secret validated the signature) == organization that actually owns Team#github_id == params.team.id`

Trace:
- `WebhooksController#verify_signature` selects the HMAC secret via `Shipit.github(organization: repository_owner)`, where `repository_owner` is read directly from the attacker-controlled payload (`params.dig('organization','login')` when there's no `repository` key) [1](#0-0) . In a multi-org config, `Shipit.github(organization:)` resolves to the config entry keyed by that same attacker-supplied org name [2](#0-1) . So the signature check only proves "whoever signed this owns the secret for the org named in the payload" — a fact the attacker satisfies with their own org's genuine secret.
- `MembershipHandler` params schema enforces only `Integer` typing on `team.id`, with no range or ownership constraint [3](#0-2) .
- `find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id)`, and only inside the creation block (executed only when no row is found) does it set `team.organization = params.organization.login`. If a `Team` row with that `github_id` already exists (belonging to a different, real organization), the block is skipped and the pre-existing record is returned untouched [4](#0-3) .
- `process` then unconditionally calls `team.add_member(member)` (for `action == 'added'`) using `User.find_or_create_by_login!(params.member.login)` — a login also fully attacker-controlled — mutating the found team's membership regardless of which org it belongs to [5](#0-4) [6](#0-5) .

Exploit flow: attacker (owning org `evil-org` with a real GitHub App installation/webhook_secret) POSTs to `/webhooks` with `X-Github-Event: membership` and a body `{"action":"added","team":{"id":<victim_team_github_id>,...},"organization":{"login":"evil-org"},"member":{"login":"attacker-gh-login"}}`, HMAC-signed with `evil-org`'s real secret. `verify_signature` passes because the secret used matches the org named in the payload. `find_or_create_team!` then resolves to the pre-existing victim `Team` row (matched purely by `github_id`), and `attacker-gh-login`'s `User` is added to it via `team.add_member`.

Existing guards fail because: `verify_signature` authenticates "org X signed this" but never re-checks that org X is the one referenced by `team.id`; `ExplicitParameters` only validates JSON types; nothing in `Team`, `Membership`, or `find_or_create_team!` scopes the `github_id` lookup by `organization`.

### Impact Explanation
If the targeted `github_id` belongs to a `Team` present in `Shipit.github_teams` (the teams configured via `github.oauth.teams` that gate access, see `User#authorized?` at [7](#0-6)  and `force_github_authentication` at [8](#0-7) ), the attacker's own `User` record becomes a member of that authorization-gating team, satisfying `teams.where(id: Shipit.github_teams.map(&:id)).exists?` and granting full authenticated access to the Shipit application — matching the High-severity category "escalation into `Shipit.github_teams` authorization." This is repeatable against any `Team#github_id` the attacker can discover (via public GitHub team browsing) and works for any org that has a legitimately configured GitHub App/webhook_secret in the multi-org config, i.e., blast radius spans every tenant sharing the same Shipit instance.

### Likelihood Explanation
Preconditions: multi-org `github:` secrets configuration (as documented in `docs/setup.md`/`secrets_double_github_app.yml`) where each org has its own real `webhook_secret`; attacker must own/administer at least one such configured org (a realistic scenario since Shipit engines are often shared across many orgs/tenants); attacker must know or guess a target team's numeric `github_id` (obtainable via GitHub's public team API without any Shipit credentials). No Shipit session, API token, or victim org's secret is required. Cost is low: one crafted HTTP POST with a correctly computed HMAC using a secret the attacker legitimately possesses.

### Recommendation
Scope the `Team` lookup by both `github_id` and the verified `organization` (i.e., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and additionally assert that `repository_owner`/the org used for `verify_signature` matches `params.organization.login` before processing membership changes, rejecting the webhook (422) on mismatch.

### Proof of Concept
Minitest (webhooks controller test), demonstrating the missing ownership check:
```ruby
test ":membership does not let another org's webhook mutate an existing team from a different org" do
  victim_team = shipit_teams(:shopify_developers) # organization: "shopify"
  # Attacker's org "evil-org" has its own real, distinct webhook_secret configured
  Shipit.stubs(:github).with(organization: "evil-org").returns(stub(verify_webhook_signature: true))

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: 'evil-org' },
    member: { login: 'attacker-gh-login' },
    repository: { owner: { login: 'evil-org' } }
  }.to_json

  assert_difference -> { victim_team.reload.members.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end

  # Binding check: the org that authenticated the request ("evil-org")
  # is NOT the org that owns this github_id ("shopify"), yet mutation succeeded.
  refute_equal 'evil-org', victim_team.reload.organization
end
```
This asserts both sides of the binding (`verified org` vs `team's actual organization`) diverge while the membership mutation still succeeds, proving the missing ownership check.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
