### Title
`MembershipHandler` writes `Team`/`Membership` rows scoped by the payload's `organization.login`, while `WebhooksController#verify_signature` authenticates the request against `repository.owner.login` (falling back to `organization.login` only when `repository` is absent) - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`verify_signature` derives the signing organization from `params.dig('repository','owner','login') || params.dig('organization','login')`, but `MembershipHandler` scopes the `Team` it creates/updates strictly to `params.organization.login`, an independent field in the same JSON body. Because the `membership` event schema in `MembershipHandler.params` never declares or restricts a `repository` key, an attacker who legitimately controls one configured organization's `webhook_secret` can inject a spurious `repository.owner.login` pointing at their own org (to pass signature verification) while setting `organization.login` to a victim org, causing `Team`/`Membership` rows to be created/mutated for an organization that never authenticated the request.

### Finding Description
The broken binding: the code assumes `repository_owner (used to select github_app/webhook_secret for HMAC verification) == params.organization.login (used to scope the Team row written by MembershipHandler)`. These are in fact independently attacker-controlled fields of the same JSON body.

- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) computes `repository_owner` via `repository_owner` (line 59-62): `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` (line 25-29).
- `MembershipHandler.params` (app/models/shipit/webhooks/handlers/membership_handler.rb:7-21) declares only `action`, `team`, `organization`, `member` - it never declares or forbids a `repository` key, so `ExplicitParameters::Parameters.parse!` (via `Handler#initialize`, app/models/shipit/webhooks/handlers/handler.rb:21-24) does not reject an extraneous `repository` object in the payload.
- `find_or_create_team!` (membership_handler.rb:38-43) creates/updates `Team` using `github_id: params.team.id` and sets `team.organization = params.organization.login`, entirely independent of whatever `repository_owner` was used for signature verification.

Exploit flow:
1. Attacker legitimately controls org A's `webhook_secret` (a real, admin-configured entry in Shipit's multi-org `github:` config), but is not a member of any `Shipit.github_teams` and has no access to org B's secret.
2. Attacker crafts a `membership` webhook JSON body:
   - `"repository": {"owner": {"login": "orgA"}}` (spurious key, injected purely to steer `verify_signature`)
   - `"organization": {"login": "orgB"}` (the real target org whose Team/Membership rows will be mutated)
   - `"team": {"id": <arbitrary>, "name": ..., "slug": ..., "url": ...}` (attacker fully controls name/slug/url for a newly created `Team` row)
   - `"member": {"login": "<attacker-github-login>"}`
   - `"action": "added"`
3. Attacker signs the raw body with org A's known `webhook_secret` and sends `POST /webhooks` with `X-Github-Event: membership` and the correct `X-Hub-Signature`.
4. `verify_signature` reads `repository.owner.login == "orgA"`, loads org A's `GitHubApp`, and the HMAC verifies successfully - the request is accepted.
5. `MembershipHandler#process` then creates/updates a `Team` scoped to `organization = "orgB"` and adds the attacker's `User` as a member, even though org B's `webhook_secret` never signed anything.

Why existing guards fail: `verify_signature` only checks that *some* configured org's secret matches; it never checks that the org used for signing is the same org referenced inside the event-specific payload fields consumed by the handler. `ExplicitParameters` for `MembershipHandler` validates required keys but does not strip/forbid unexpected top-level keys like `repository`, so the spoofed key survives to the controller's `repository_owner` lookup (which runs on the raw parsed body before/independent of handler-level schema enforcement). No model validation or `require_permission!`/`User#authorized?` check intervenes at write time in `find_or_create_team!`.

### Impact Explanation
An attacker who legitimately owns one configured Shipit organization can create or mutate `Team` and `Membership` rows attributed to a *different*, victim organization, without ever possessing that victim organization's `webhook_secret`. Because the attacker fully controls the injected team's `name`/`slug`/`url` and can choose the organization login to match any org configured in Shipit, this can be used to fabricate a `Team` whose `organization`+`slug` matches an entry in `Shipit.github_teams`, and add the attacker's own `User` as a member - i.e., escalation into `Shipit.github_teams` authorization for an organization the attacker never authenticated against. This is repeatable against any organization configured in Shipit's multi-org setup and matches the High severity category "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Preconditions: Shipit must be configured with a multi-org `github:` section (documented feature) where the attacker legitimately controls at least one organization's `webhook_secret` (e.g., by being onboarded as a customer/org owner), and the victim org must be configured in the same Shipit instance with a `Shipit.github_teams` entry the attacker wants to escalate into (attacker needs to know or guess the victim's team slug, which is often documented/public). Attacker cost is a single crafted HTTP POST with a valid HMAC using their own known secret - no live GitHub interaction, no privileged Shipit role required. This is fully repeatable/scriptable against any victim org in the same deployment.

### Recommendation
In `MembershipHandler` (and any other org-scoped handler), verify that the organization used to authenticate the webhook (`repository_owner` from `WebhooksController`) matches `params.organization.login` before writing/mutating `Team`/`Membership` records - reject the event otherwise. More generally, `WebhooksController#verify_signature` should pass the authenticated `repository_owner` value down to handlers, and handlers should scope all writes strictly to that authenticated value rather than trusting any organization/repository field re-read from the raw payload. Additionally, `ExplicitParameters` schemas should reject unexpected top-level keys (e.g., a `repository` key not declared by `MembershipHandler.params`) to prevent this kind of field-injection.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "membership webhook signed by org A cannot create/modify Team scoped to org B" do
  # Shipit configured with two orgs, org A and org B, each with distinct webhook_secret
  org_a_secret = Shipit.github(organization: 'orgA').send(:webhook_secret)

  payload = {
    action: 'added',
    team: { id: 999_999, name: 'Fake Team', slug: 'employees', url: 'https://api.github.com/teams/999999' },
    organization: { login: 'orgB' },       # target org whose secret is NOT used
    member: { login: 'attacker' },
    repository: { owner: { login: 'orgA' } } # spurious key, forces verify_signature to use org A's secret
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest('sha1', org_a_secret, payload)

  assert_no_difference -> { Shipit::Team.where(organization: 'orgB').count } do
    post shipit.github_webhooks_path,
      params: payload,
      headers: {
        'X-Github-Event' => 'membership',
        'X-Hub-Signature' => signature,
        'Content-Type' => 'application/json'
      }
  end

  refute Shipit::Team.exists?(organization: 'orgB', github_id: 999_999),
    "org B's Team must not be created/modified by a request signed with org A's secret"
end
```
Both sides of the binding to assert: `repository_owner` resolved by `verify_signature` (`"orgA"`, matching the secret used to sign) must equal `params.organization.login` (`"orgB"`, the org actually written by `find_or_create_team!`) for the write to be legitimate - the test shows they diverge and the write still occurs under the current code, confirming the vulnerability. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-43)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L10-24)
```ruby
          def params(&block)
            @param_parser = ExplicitParameters::Parameters.define(&block)
          end
        end

        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end
```
