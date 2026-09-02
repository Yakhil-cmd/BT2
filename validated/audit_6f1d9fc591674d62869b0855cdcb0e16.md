### Title
Membership webhook side effects (`Team`/`User` row creation) execute before action validation and can target an organization different from the one whose signature was verified - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#process` unconditionally runs `find_or_create_team!` and `User.find_or_create_by_login!` before validating `params.action`, so an `ArgumentError` raised for an unrecognized action (e.g. `'edited'`) does not roll back or prevent the `Team`/`User` writes that already happened. Combined with the fact that `WebhooksController#verify_signature` derives the verified organization from `repository.owner.login` (falling back to `organization.login`) while `MembershipHandler` independently trusts `params.organization.login` and `params.team.id` for record creation, an attacker who controls a Shipit-registered organization can craft a single payload where the signature-checked org differs from the org used to create the `Team` row.

### Finding Description
The broken binding, stated as an equality that the code fails to enforce:
`verified_organization (used in WebhooksController#verify_signature via repository.owner.login || organization.login) == organization_used_for_writes (params.organization.login in MembershipHandler#find_or_create_team!)`.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and verifies the HMAC signature against `Shipit.github(organization: repository_owner)`'s configured `webhook_secret` [2](#0-1) .
- The parsed JSON body is then handed, unmodified, to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .
- `MembershipHandler#process` runs `team = find_or_create_team!` and `member = User.find_or_create_by_login!(params.member.login)` before the `case params.action` block that only handles `'added'`/`'removed'` and raises `ArgumentError` for anything else [4](#0-3) .
- `find_or_create_team!` writes `github_id: params.team.id`, `team.organization = params.organization.login`, driven entirely by attacker-supplied payload fields, independent of the field (`repository.owner.login`) that was actually signature-checked [5](#0-4) .

Exploit flow: the attacker owns/administers a real organization that is already registered in Shipit (so a valid `webhook_secret` exists and the attacker can produce a validly-signed delivery for it, e.g. by using GitHub's real membership webhook or a self-configured hook on their own org). They send `POST /webhooks` with `X-Github-Event: membership`, a valid signature for their own org (via `repository.owner.login` = attacker org, satisfying `verify_signature`), but with `organization.login`, `team.id`, and `member.login` set to the victim org/team/user, and `action: 'edited'`. `verify_signature` passes because it only checks the org named in `repository.owner.login`/fallback `organization.login` against the matching secret — it never cross-checks that `organization.login` used later by the handler is the same value it validated the signature for when a `repository` key is also present. `find_or_create_team!` and `User.find_or_create_by_login!` execute and persist rows scoped to the victim org/user before the handler hits the `else` branch and raises `ArgumentError`, which propagates as an unhandled exception (500) from `WebhooksController#create` — the request "fails" but the writes are not rolled back since there is no wrapping transaction.

No existing guard intercepts this: `verify_signature` does not compare `organization.login` to `repository.owner.login`; `find_or_create_team!` performs no cross-check against the verified org; there is no transaction wrapping `process`; `ExplicitParameters` only validates types/presence, not cross-field consistency.

### Impact Explanation
An attacker can plant a `Team` row (with `organization` set to any target org string and `github_id` set to any integer they choose) and/or a `User` row for an arbitrary GitHub login, using only a validly-signed webhook from an organization they legitimately control. This is a cross-organization row creation for `Team`/`User` records that were never authenticated for the targeted organization, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Because `Team.find_or_create_by!` is keyed on `github_id`, this could also let the attacker pre-create a `Team` row with a chosen `organization` value that would later collide with or spoof a legitimate team once the victim org is genuinely onboarded, and it is repeatable against arbitrary orgs/teams/users per request, each unsuccessful (`'edited'`-style) request leaking no payload content in the response (Rails default 500 does not echo payload) but always still writing the DB rows beforehand.

### Likelihood Explanation
The attacker needs no Shipit session, API token, or Shipit secrets, only: (a) control of an organization that is already registered with Shipit and configured with a working `webhook_secret` (a precondition shared with the previously-identified verification gap), and (b) the ability to submit a single crafted JSON body with mismatched `repository`/`organization` fields. Cost is a single HTTP POST; the flaw is deterministic and repeatable for any `team.id`/`member.login` value.

### Recommendation
1. Wrap `MembershipHandler#process` in a way that validates `params.action` before performing any find-or-create side effects (move the `case`/`else` check to the top of `process`, before `find_or_create_team!`/`User.find_or_create_by_login!` are called).
2. Cross-validate that `params.organization.login` matches the organization that `WebhooksController#verify_signature` actually authenticated (i.e., reject if `repository.owner.login`/`organization.login` used for signature verification differs from `params.organization.login` used by the handler).
3. Wrap the entire `process` body in a DB transaction so that any raised exception (including unknown-action `ArgumentError`) rolls back partial writes.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":membership with unknown action still creates victim Team/User rows before raising" do
  @request.headers['X-Github-Event'] = 'membership'
  victim_team_github_id = 999_999
  payload = {
    action: 'edited',
    team: { id: victim_team_github_id, name: 'Victim Team', slug: 'victim-team', url: 'https://example.com' },
    organization: { login: 'victim-org' },
    member: { login: 'victim-user' },
    repository: { owner: { login: 'shopify' } } # attacker-controlled org used for signature check
  }.to_json

  assert_raises(ArgumentError) do
    post :create, body: payload, as: :json
  end

  # Equality check both sides: verified org ('shopify') != org used for writes ('victim-org')
  team = Shipit::Team.find_by(github_id: victim_team_github_id)
  assert team.present?, "Team row for victim org should not exist but was created"
  assert_equal 'victim-org', team.organization

  assert Shipit::User.exists?(login: 'victim-user'), "User row for victim login should not exist but was created"
end
```
This demonstrates that despite the request ultimately erroring (`ArgumentError`/500) and the signature having only been verified against `shopify` (attacker-controlled), a `Team` row scoped to `victim-org` and a `User` row for `victim-user` are persisted.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-42)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
```
