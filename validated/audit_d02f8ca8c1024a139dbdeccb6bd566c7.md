### Title
Cross-organization team membership mutation via unverified `team.id` in `membership` webhook - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` and `#find_or_create_team!` trust `params.team.id` and `params.organization.login` from the webhook body without checking that the organization whose `webhook_secret` verified the request actually owns the `Team` record being mutated. In a multi-organization Shipit deployment (explicitly supported per `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`), an attacker who controls one trusted organization can send a validly-signed `membership` webhook naming another organization's real `team.id` (public/observable GitHub data) and any known Shipit user's login, causing `team.members.delete(member)` to strip that user's membership from the victim org's team.

### Finding Description
The binding that should hold is: `organization owning the Team record mutated` == `organization whose webhook_secret verified request.raw_post` (i.e. the org resolved by `WebhooksController#repository_owner` and passed to `Shipit.github(organization:)`).

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . GitHub's real `membership` event payload has no top-level `repository` key, so `repository_owner` resolves to `params['organization']['login']` — a field fully controlled by the sender of the webhook, and it is used purely to pick *which org's secret* to verify against, not to bind the payload's other fields to that org.
2. Verification succeeds via `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` using that org's own `webhook_secret` [2](#0-1) [3](#0-2) . This only proves the request came from the org named in `organization.login` — it proves nothing about the `team` object also embedded in the same payload.
3. `MembershipHandler#find_or_create_team!` looks up (or creates) a `Team` keyed **solely** on `github_id: params.team.id`, with `team.organization = params.organization.login` only assigned inside the `find_or_create_by!` block, i.e. only on first creation [4](#0-3) . If a `Team` with that `github_id` already exists (created earlier by the legitimate victim org), the lookup returns the existing record untouched — `team.organization` is never re-validated against the verified `organization.login`.
4. `process` then resolves `member = User.find_or_create_by_login!(params.member.login)` (attacker-chosen) and, for `action == 'removed'`, executes `team.members.delete(member)` directly on the victim's real `Team` [5](#0-4) .

Exploit: attacker controls "OrgAttacker", a legitimate org onboarded to the same Shipit instance with its own `webhook_secret` (multi-org config is a documented, supported deployment mode — see `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`). Attacker POSTs to `/webhooks` with `X-Github-Event: membership`, body `{"action":"removed","organization":{"login":"OrgAttacker"},"team":{"id":<victim's real team github_id>,"name":"x","slug":"x","url":"x"},"member":{"login":"<victim operator's github login>"}}`, signed with `HMAC-SHA1(OrgAttacker's webhook_secret, raw_body)`. `verify_signature` passes because it only checks the signature against OrgAttacker's own secret. `find_or_create_team!` finds the pre-existing victim `Team` by `github_id` and `team.members.delete(member)` removes the real membership — a write to another organization's authorization state performed under provenance that only proves the attacker's own organization sent it.

None of the existing guards catch this: `verify_signature` verifies HMAC per-org correctly but the org selected for verification is not cross-checked against the team/org fields consumed downstream; `ExplicitParameters` schema only validates types/presence, not cross-org ownership; there is no `require_permission!`/`User#authorized?` check in this handler since it's a server-to-server webhook flow.

### Impact Explanation
An attacker with control of any one organization configured in Shipit's multi-org `github` secrets can silently revoke another organization's `Team` membership (removing a user from `Shipit.github_teams`-backed authorization data) without ever touching the victim org's webhook secret. This is a cross-tenant write authorized only by the attacker's own organization's provenance, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team") — here it is a team/authorization-state mutation across tenants. Repeatable for any team `github_id` and any user login known to the attacker (both are discoverable via public GitHub UI/API), and it is directly usable to strip a legitimate operator's `Shipit.github_teams` privilege, which is itself a High-severity primitive for further escalation (loss of authorization for the victim user).

### Likelihood Explanation
Requires: (1) Shipit configured with multiple organizations (multi-org `github` secrets schema), and (2) attacker legitimately controls/administers one of those configured organizations (able to set up its GitHub App webhook and thus know/derive its `webhook_secret` for signing). Given those preconditions — which are attacker-achievable by simply being a trusted-but-lower-privileged org owner on a shared Shipit instance, not requiring any Shipit or victim secret — the attack is a single crafted HTTP POST, fully repeatable, and does not require live GitHub interaction to prove (Team/User/Membership records are local ActiveRecord state).

### Recommendation
In `MembershipHandler`, after resolving/creating the `Team`, verify that `team.organization.casecmp?(params.organization.login)` (i.e. the org that verified the webhook must equal the org that owns the existing `Team` record) before performing `add_member`/`team.members.delete`; if they differ, drop/reject the event. Additionally, the `WebhooksController#repository_owner` fallback to `organization.login` should be documented/scoped as "verification organization" only, never conflated with authorization on nested payload objects like `team`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (illustrative addition)
test ":membership 'removed' from a different verified org can delete a victim org's membership" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: X
  victim_membership = victim_team.memberships.create!(user: shipit_users(:walrus))

  attacker_org_secret = 'attacker-secret'
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    Shipit::GitHubApp.new('attacker-org', webhook_secret: attacker_org_secret)
  )

  body = {
    action: 'removed',
    team: { id: victim_team.github_id, name: 'x', slug: 'x', url: 'x' },
    organization: { login: 'attacker-org' }, # binding under test: verifying org
    member: { login: shipit_users(:walrus).login }
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', attacker_org_secret, body)}"
  @request.headers['X-Github-Event'] = 'membership'
  @request.headers['X-Hub-Signature'] = signature

  # BEFORE: attacker_org ('attacker-org') != victim_team.organization ('shopify')
  refute_equal 'attacker-org', victim_team.organization

  assert_difference -> { victim_team.memberships.count }, -1 do
    post :create, body:, as: :json
    assert_response :ok
  end

  # AFTER: mutation happened despite the equality never holding
  refute victim_team.reload.members.include?(shipit_users(:walrus))
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
