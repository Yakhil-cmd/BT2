### Title
Cross-tenant webhook forgery lets an attacker's own org's signature authorize writing an arbitrary victim organization into `Team#organization` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which org's `webhook_secret` authenticates a webhook using `repository_owner`, which prefers `params.dig('repository','owner','login')` over `params.dig('organization','login')`. `MembershipHandler#find_or_create_team!` instead trusts `params.organization.login` to stamp `Team#organization`. Because the request body is fully attacker-controlled JSON, an attacker who legitimately owns a Shipit-configured org can inject a `repository` key naming their own org (so the signature check passes with their own known secret) while setting the `organization` key to an arbitrary victim org string that gets persisted onto the `Team` record.

### Finding Description
The broken binding: `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` authenticates the request using **`repository_owner`** [1](#0-0)  computed from `params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) , but `MembershipHandler#find_or_create_team!` persists **`params.organization.login`** into `Team#organization` [3](#0-2) . These two org identifiers are never asserted equal.

Real GitHub `membership` events never include a top-level `repository` key, so in legitimate traffic `repository_owner` resolves to `params.organization.login` and the two values coincide. But the controller parses the raw POST body with no schema restricting which top-level keys can be present before signature verification runs (`before_action :check_if_ping, :drop_unhandled_event, :verify_signature` all execute against attacker-supplied `params` prior to any `ExplicitParameters` validation, which only happens later inside `Handler#call`) [4](#0-3) . An attacker who administers their own Shipit-configured org (and therefore knows that org's `webhook_secret`) can craft a `membership` payload like:
```json
{
  "action": "added",
  "team": {"id": 48, "name": "x", "slug": "x", "url": "https://example.com"},
  "organization": {"login": "victim-org"},
  "member": {"login": "attacker-login"},
  "repository": {"owner": {"login": "attacker-org"}}
}
```
signed with `attacker-org`'s own `webhook_secret`. `verify_signature` resolves `repository_owner` to `attacker-org`, fetches `Shipit.github(organization: 'attacker-org')`, and the HMAC check succeeds because the attacker knows that secret [5](#0-4) . The request is accepted and dispatched to `MembershipHandler#process`, which creates/updates a `Team` row whose `organization` is `victim-org` and adds the attacker as a member [6](#0-5) .

No existing guard closes this gap: `drop_unhandled_event` only checks the event type header, `verify_signature` only checks HMAC against whichever org string `repository_owner` happens to pick, and `MembershipHandler`'s `ExplicitParameters` schema validates types/presence of `organization.login` but never cross-checks it against the `repository` key or against whichever org authenticated the request [7](#0-6) .

### Impact Explanation
An attacker with a legitimately configured but unrelated org in a multi-tenant Shipit deployment can forge webhook authentication and cause a `Team` record to be created/updated and stamped with an arbitrary victim organization string, and simultaneously add themselves as a member of that team. This is a payload authenticated under one org mutating a `Team` record logically belonging to another org — matching the "payload for one repository mutating another's ... team" Critical category. Repeatable against any org string the attacker chooses to write into `Team#organization`, and blast radius spans every tenant configured in the same Shipit instance since the org-to-secret mapping is entirely attacker-selectable via the `repository` key.

### Likelihood Explanation
Requires only that the attacker's own org be configured in the multi-org Shipit deployment (a precondition explicitly stated in the question) — no access to the victim org's secret, no Shipit session, and no privileged role is needed. The attack is a single crafted HTTP POST with a correctly-signed body using a secret the attacker already legitimately possesses. This is low-cost and fully repeatable.

### Recommendation
Derive `repository_owner` (used for signature verification) and any organization value used by handlers from the same single source of truth, and reject payloads where they diverge. Specifically, do not allow the `repository` key to override `organization` for events that GitHub never emits with both keys, and/or have handlers validate that `params.organization.login` (or `params.repository.owner.login`) matches the org actually used to authenticate the request (e.g., pass the authenticated org from `verify_signature` into the handler and assert equality) before writing to `Team#organization`.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb`, add a multi-org secrets fixture (as in `test/dummy/config/secrets_double_github_app.yml`) with two orgs, e.g. `attacker-org` and `victim-org`, each with distinct `webhook_secret`s. Then:
```ruby
test ":membership payload signed under attacker-org writes victim-org into Team#organization" do
  request.headers['X-Github-Event'] = 'membership'
  body = {
    action: 'added',
    team: { id: 999, name: 'x', slug: 'x', url: 'https://example.com' },
    organization: { login: 'victim-org' },
    member: { login: 'attacker' },
    repository: { owner: { login: 'attacker-org' } }
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', ATTACKER_ORG_SECRET, body)}"
  @request.headers['X-Hub-Signature'] = signature

  assert_equal 'attacker-org', Shipit::WebhooksController.new.send(:repository_owner) rescue nil # sanity on resolution
  post :create, body: body, as: :json
  assert_response :ok

  team = Shipit::Team.find_by(github_id: 999)
  assert_equal 'victim-org', team.organization # attacker-chosen org, never authenticated
end
```
This demonstrates the equality `authenticated_org (attacker-org) != Team#organization (victim-org)` after the request, confirming the binding violation.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-16)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
