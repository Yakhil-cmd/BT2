### Title
Membership webhook authenticates against `repository.owner.login`/fallback organization while `MembershipHandler` scopes the `Team` write to `params.organization.login`, allowing cross-organization team/membership escalation - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` resolves the authenticating organization from `repository.owner.login` (falling back to `organization.login`), and skips HMAC verification entirely whenever that organization's `webhook_secret` is blank. `MembershipHandler#find_or_create_team!` independently trusts `params.organization.login` to scope the `Team` record and grants membership to `params.member.login` via `team.add_member(member)`, with no check that this value matches the organization that actually authenticated the request.

### Finding Description
The broken binding: `organization whose webhook_secret verified the payload (repository_owner = params.dig('repository','owner','login') || params.dig('organization','login'), checked in app/controllers/shipit/webhooks_controller.rb:24-30,59-62)` should equal `organization named in params.organization.login that MembershipHandler writes into Team#organization (app/models/shipit/webhooks/handlers/membership_handler.rb:38-42)`.

`GitHubApp#verify_webhook_signature` in `lib/shipit/github_app.rb:76-83` contains `return true unless webhook_secret` — if the resolved organization has no configured `webhook_secret`, signature verification is a no-op and any payload is accepted. Because `repository_owner` is computed from the `repository.owner.login` field of the fully attacker-controlled JSON body (`request.raw_post` is parsed as-is), an attacker can craft a payload that sets `repository.owner.login` to an org that Shipit has configured but without a `webhook_secret` (to trivially pass `verify_signature`), while setting `organization.login` to a real, privileged organization present in `Shipit.github_teams` (e.g. `shopify`). `MembershipHandler#process` and `#find_or_create_team!` never reference `repository_owner`; they only read `params.organization.login` (line 41) and `params.member.login` (line 24, 19-20), so the handler creates/finds a `Team` scoped to the privileged org and adds an attacker-chosen `member.login` to it via `team.add_member(member)` (line 28), regardless of which organization's secret (or lack thereof) actually authenticated the request.

Existing guards do not close this gap: `drop_unhandled_event` and `check_if_ping` only gate on event type; the `ExplicitParameters` schema in `MembershipHandler` only validates types/presence of `action`, `team`, `organization.login`, and `member.login` — it performs no cross-field check against `repository_owner`; `verify_signature` itself only authenticates whichever organization `repository_owner` happens to name, and that name is attacker-supplied and decoupled from `organization.login`.

### Impact Explanation
A successful request creates or mutates a `Team` record for the victim organization and inserts a `Membership` linking an arbitrary attacker-controlled GitHub login to that team, without ever possessing or forging the victim organization's `webhook_secret`. If the victim organization is one referenced by `Shipit.github_teams` for authorization decisions, this is a direct escalation into `Shipit.github_teams` authorization for an attacker-chosen login — matching the "High: escalation into `Shipit.github_teams` authorization" impact category. The attack is repeatable against any organization name the attacker chooses to place in `organization.login`, independent of that organization's own secret, as long as some other configured organization in the same Shipit deployment has a blank `webhook_secret`.

### Likelihood Explanation
The precondition is that at least one organization configured in the Shipit deployment (via `Shipit.github`) has no `webhook_secret` set — `lib/shipit/github_app.rb:76-77` makes verification a no-op in that case. This is a plausible and previously-seen multi-tenant configuration (the repo's own test fixtures, e.g. `test/dummy/config/secrets_double_github_app.yml`, demonstrate multiple configured organizations, and nothing in the code prevents one of them from omitting `webhook_secret`). Given that precondition, the attacker needs no session, token, or secret — only the ability to POST arbitrary JSON to `/webhooks` with a crafted `repository.owner.login`/`organization.login` mismatch, which is fully within the stated attacker capability. The attack is trivially repeatable per request.

### Recommendation
Bind authorization scope to the value that was actually authenticated: make `MembershipHandler` (and other org-scoped handlers) use the same `repository_owner`/authenticated-organization value the controller used for signature verification when scoping `Team#organization`, rather than trusting `params.organization.login` independently. Additionally, treat a blank `webhook_secret` as a misconfiguration rather than an implicit bypass — require every configured organization to define a `webhook_secret`, or explicitly reject events whose `organization.login`/`repository.owner.login` does not equal the organization resolved for signature verification.

### Proof of Concept
Minitest plan (webhooks controller test, no live GitHub):
1. Configure two organizations in test config: `victim-org` (with a `webhook_secret`, and present in `Shipit.github_teams`) and `no-secret-org` (with `webhook_secret` blank/nil).
2. Build payload:
```ruby
payload = {
  action: 'added',
  team: { id: 999, name: 'Evil', slug: 'evil', url: 'https://example.com' },
  organization: { login: 'victim-org' },
  member: { login: 'attacker-login' },
  repository: { owner: { login: 'no-secret-org' } }
}.to_json
```
3. POST to `/webhooks` with `X-Github-Event: membership` and an arbitrary/missing `X-Hub-Signature` header (no real signature required since `no-secret-org` has no secret).
4. Assert:
   - `response` is `:ok` (signature check passed because `repository_owner` resolved to `no-secret-org`, i.e. left side of the equality = `no-secret-org`).
   - `Team.find_by(github_id: 999).organization == 'victim-org'` (right side of the equality), demonstrating `'no-secret-org' != 'victim-org'` yet the write succeeded.
   - `Team.find_by(github_id: 999).members.map(&:login)` includes `'attacker-login'`.

This confirms the two sides of the claimed binding diverge and that divergence is exploitable to write `Team`/`Membership` records for an organization whose secret never authenticated the request. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-44)
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
      end
```

**File:** test/controllers/webhooks_controller_test.rb (L94-127)
```ruby
    test "verifies webhook signature" do
      commit = shipit_commits(:first)

      payload = { "sha" => commit.sha, "state" => "pending", "target_url" => "https://ci.example.com/1000/output" }.merge(repository_params).to_json
      signature = 'sha1=4848deb1c9642cd938e8caa578d201ca359a8249'

      @request.headers['X-Github-Event'] = 'push'
      @request.headers['X-Hub-Signature'] = signature

      Shipit.github(organization: 'shopify').expects(:verify_webhook_signature).with(signature, payload).returns(false)

      post :create, body: payload, as: :json
      assert_response :unprocessable_entity
    end

    test "unknown github organization logs and returns unprocessable entity" do
      @request.headers['X-Github-Event'] = 'push'

      payload = JSON.parse(payload(:push_master))
      payload["repository"]["owner"]["login"] = "unknown-org"

      Shipit.stubs(:github).raises(Shipit::GithubOrganizationUnknown.new("unknown-org"))
      Rails.logger.expects(:warn).with([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=push",
        "repository_owner=unknown-org",
        "unknown_organization=unknown-org",
        "status=422"
      ].join(' '))

      post :create, body: payload.to_json, as: :json
      assert_response :unprocessable_entity
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L208-218)
```ruby
    def membership_params
      { action: 'added', team: team_params, organization: { login: 'shopify' }, member: { login: 'walrus' } }.merge(repository_params)
    end

    def team_params
      { id: shipit_teams(:shopify_developers).id, slug: 'developers', name: 'Developers', url: 'http://example.com' }
    end

    def repository_params
      { repository: { owner: { login: 'shopify' } } }
    end
```
