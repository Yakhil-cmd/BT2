Confirmed: the `membership` event handler is global and not scoped to any organization or `GithubHook::Organization` subscription. This confirms the vulnerability.

### Title
Cross-organization Team membership escalation via colliding `team.id` in `MembershipHandler` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` resolves a `Team` solely by the numeric `team.id` from the webhook payload, via `Team.find_or_create_by!(github_id: params.team.id)` [1](#0-0) . GitHub team IDs are globally unique across all organizations, but the handler never verifies that `params.organization.login` (the org whose webhook secret authenticated the request) actually matches the `organization` column already stored on the found `Team`. This lets an attacker who legitimately controls a webhook subscription for their OWN org send a `membership` event naming a `team.id` that belongs to a different org's already-persisted `Team`, causing a `Membership` row to be written into that foreign `Team`.

### Finding Description
The broken binding: `Membership row exists for Team(github_id=X) == GitHub actually reported a membership change for github_id=X's real org`. After this bug, a `Membership` can be created for `Team(github_id=X, organization="victim-org")` even though the webhook was signed and authenticated for `organization="attacker-org"`.

Path: `WebhooksController#create` dispatches strictly by `X-Github-Event` header via `Shipit::Webhooks.for_event(event)` [2](#0-1) , with `'membership' => [Handlers::MembershipHandler]` registered globally, not scoped per-organization [3](#0-2) . `verify_signature` only checks the HMAC against the webhook secret configured for `repository_owner`, which for membership events falls back to `params.dig('organization','login')` [4](#0-3) . This means the signature check only proves the request was legitimately signed for `organization.login`'s org — it says nothing about `team.id`.

`MembershipHandler#process` then does:
```
team = find_or_create_team!      # Team.find_or_create_by!(github_id: params.team.id)
member = User.find_or_create_by_login!(params.member.login)
team.add_member(member) if action == 'added'
```
`find_or_create_by!`'s block (which sets `team.organization = params.organization.login`) only executes when a NEW record is created; when a `Team` with that `github_id` already exists (created earlier by the real owning org's genuine membership webhooks), the existing record — with its real `organization` — is returned untouched, and `add_member` is invoked on it [5](#0-4) .

Attacker request: attacker legitimately administers `github: cyclimse:` in Shipit's config (a real, separate org onboarded to this Shipit instance) and knows its `webhook_secret`. Using fixture data as an example, `Team(github_id: 1, organization: "shopify")` already exists [6](#0-5) . The attacker POSTs to `/webhooks` with header `X-Github-Event: membership`, HMAC-signed with cyclimse's own secret, body:
```json
{"action":"added","team":{"id":1,"name":"x","slug":"x","url":"http://x"},
 "organization":{"login":"cyclimse"},"member":{"login":"attacker-login"}}
```
`verify_signature` succeeds because the signature is valid for `cyclimse` (the real signer). `drop_unhandled_event` passes because `membership` has a registered global handler. Inside the handler, `Team.find_or_create_by!(github_id: 1)` returns the existing shopify `Team`, and `team.add_member(attacker_user)` inserts a `Membership` linking the attacker's user to the shopify team — a team GitHub never reported this user as a member of.

No existing guard prevents this: `verify_signature` validates only the signer's org, not the referenced team's org; the `ExplicitParameters` schema only validates types/presence, not cross-references; `find_or_create_team!` has no check like `team.organization == params.organization.login`.

### Impact Explanation
If the victim `Team` (e.g. `shopify/developers`) is one of the entries configured in `Shipit.github_teams` (via `github.oauth.teams`), then `User#authorized?` — which checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6)  — will now return true for the attacker's user, granting them authenticated access to the whole Shipit instance for that tenant (i.e., `force_github_authentication`'s authorization gate is bypassed) [8](#0-7) . This is repeatable against any `Team` github_id the attacker can observe (public GitHub team API, prior pings, etc.), across any tenant/org configured in the same Shipit instance, as long as the attacker legitimately controls one org's webhook secret. This matches the "High - escalation into `Shipit.github_teams` authorization" category; it can cascade toward Critical if that authorization gate is the only thing standing between the attacker and deploy/merge actions.

### Likelihood Explanation
Preconditions: a multi-tenant Shipit deployment (multiple orgs configured under `github:` in secrets, as documented) [9](#0-8) ; attacker legitimately controls one of those onboarded orgs and its webhook secret; attacker knows or can discover a target team's numeric GitHub `id` (publicly queryable via GitHub's team API or observed from a prior legitimate ping). No Shipit secrets, session, or API token are needed — the attacker acts only within their own legitimately configured org, so likelihood is moderate-to-high in any multi-org deployment.

### Recommendation
In `find_or_create_team!`, verify that the resolved `Team`'s `organization` matches `params.organization.login` before performing any membership mutation; if it doesn't match, reject/raise instead of silently reusing the cross-org record. Consider scoping the lookup as `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)` so a mismatch results in an insert-collision/validation error rather than silent reuse of another org's team.

### Proof of Concept
minitest (in `test/controllers/webhooks_controller_test.rb` style, not run live against GitHub):
```ruby
test ":membership webhook signed for org A can add a member to org B's team (cross-org escalation)" do
  victim_team = shipit_teams(:shopify_developers) # github_id: 1, organization: "shopify"
  attacker_org = "cyclimse"

  GithubHook.any_instance.stubs(:verify_signature).returns(true)
  Shipit.stubs(:github).with(organization: attacker_org).returns(stub(verify_webhook_signature: true))

  @request.headers['X-Github-Event'] = 'membership'
  body = {
    action: 'added',
    team: { id: victim_team.github_id, name: 'Developers', slug: 'developers', url: 'http://example.com' },
    organization: { login: attacker_org },
    member: { login: 'attacker-login' }
  }.to_json

  assert_difference -> { victim_team.reload.members.count }, 1 do
    post :create, body: body, as: :json
    assert_response :ok
  end

  attacker_user = User.find_by(login: 'attacker-login')
  assert_includes victim_team.members, attacker_user
  assert_equal 'shopify', victim_team.reload.organization # unchanged: proves cross-org write, not a legitimately-created shopify record
end
```
Assert both sides of the binding: `victim_team.organization == "shopify"` (unchanged, real owner) while `victim_team.members.include?(attacker_user)` becomes true off a request whose authenticated signer was `"cyclimse"` — proving GitHub never reported this membership for the real (`shopify`) org.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks.rb (L19-21)
```ruby
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
```

**File:** test/fixtures/shipit/teams.yml (L3-9)
```yaml
shopify_developers:
  id: 1
  github_id: 1
  organization: shopify
  slug: developers
  name: Developers
  api_url: https://example.com/shopify/developers
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
