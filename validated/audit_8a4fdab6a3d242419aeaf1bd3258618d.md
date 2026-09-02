### Title
`MembershipHandler#process` 'removed' branch trusts unscoped `team.id` from any verified organization, letting cross-org webhooks delete `Membership` rows for teams they don't own - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::MembershipHandler#process` looks up the target `Team` solely by `params.team.id`/`github_id`, without checking that the organization which cryptographically verified the webhook actually owns that team. Because `Team` records are looked up by a globally-unique `github_id` and `verify_signature` only proves "some configured org's secret signed this payload", an attacker who controls any org onboarded to Shipit (their own) can forge a `membership`/`removed` event naming a team `github_id` belonging to a different, unrelated organization and remove a legitimate operator's `Membership`.

### Finding Description
The broken binding, stated explicitly: `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` proves only that **`repository_owner` (the organization named in the attacker-controlled JSON payload) == an organization configured in Shipit with its own `webhook_secret`**. It does **not** prove that `repository_owner == the organization that actually owns `Team.find_or_create_by!(github_id: params.team.id)``.

Code path:
- `WebhooksController#verify_signature` derives `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) , both of which are attacker-supplied JSON fields for a `membership` event (membership events have no `repository` key, so the `organization.login` value the attacker writes is used) [2](#0-1) .
- It then fetches `Shipit.github(organization: repository_owner)` and verifies the HMAC against **that** org's configured `webhook_secret` [3](#0-2) . If the attacker names their own onboarded organization in `organization.login`, they sign with their own real secret and the check passes.
- `MembershipHandler#process` then does `team = find_or_create_team!` which resolves purely by `params.team.id` via `Team.find_or_create_by!(github_id: params.team.id)` [4](#0-3) , with no comparison against `repository_owner`/the verified organization. On `'removed'`, it calls `team.members.delete(member)` [5](#0-4) , deleting the `Membership` join row for the `member` resolved via `User.find_or_create_by_login!(params.member.login)` [6](#0-5) .

Exploit: attacker registers/owns an org that is configured as a secondary GitHub App/org in Shipit (has its own `webhook_secret`), then POSTs to `/webhooks` with header `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with their own org's secret, and a JSON body where `organization.login` = attacker's org, `team.id` = the real `github_id` of a team belonging to a victim org in `Shipit.github_teams`, and `member.login` = a legitimate operator's GitHub login, `action: 'removed'`. `verify_signature` passes because it only checks the attacker's own org's secret. `find_or_create_team!` finds the existing victim `Team` row by `github_id` (already created earlier from legitimate `membership`/`added` events for that team) and deletes the operator's membership.

This is exploitable only in deployments where Shipit is configured with more than one GitHub organization/app (multi-tenant `Shipit.github` config), giving the attacker control of a legitimate-but-unrelated org's webhook secret. `drop_unhandled_event`, `ExplicitParameters` schema, and `verify_webhook_signature` all pass in this scenario since they check the wrong dimension (payload well-formedness and *some* org's secret) rather than team-ownership.

### Impact Explanation
The write is a `Membership` deletion for a `Team` in `Shipit.github_teams`, directly corrupting `User#authorized?` (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`) [7](#0-6) . This strips deploy/authorization access from a legitimate operator without any real GitHub-side change, an authorization-model corruption gated behind a webhook whose origin does not match the resource it mutates — a cross-tenant write (attacker's verified org mutating a victim org's team membership). It is repeatable against any team `github_id` the attacker can guess or observe (team IDs are not secret) and any known operator login.

### Likelihood Explanation
Requires: (1) Shipit configured with more than one onboarded GitHub organization (so the attacker legitimately controls one org's `webhook_secret` while the victim team belongs to another), and (2) the victim `Team` row must already exist (created from a prior legitimate `added` event). Given those, the attack is a single crafted HTTP POST with a correctly HMAC-signed body using a secret the attacker legitimately possesses — no Shipit session, token, or victim secret needed. Feasibility is moderate/high in multi-org Shipit deployments and depends on that specific deployment shape, which is why it's not universally exploitable in a single-org install (there the attacker would need the org's own secret, which is out of scope by the rules).

### Recommendation
In `MembershipHandler#process` (and `find_or_create_team!`), scope the team lookup by the verified organization, e.g. require `params.organization.login == team.organization` (or pass the verified `repository_owner`/organization into the handler and assert equality) before mutating `Team#members`, rejecting/logging the event if the verified organization does not match the team's recorded `organization`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/membership_handler_test.rb`, out-of-scope path noted only for reference, actual proof would live under `test/`):
1. Create `victim_team = Team.create!(github_id: 555, organization: 'victim-org', slug: 'ops')`.
2. Create `legit_user = User.create!(login: 'operator')` and `Membership.create!(team: victim_team, user: legit_user)`.
3. Assert precondition: `assert Membership.exists?(team: victim_team, user: legit_user)`.
4. Build a `membership` payload with `action: 'removed'`, `organization: { login: 'attacker-org' }`, `team: { id: 555, name: 'ops', slug: 'ops', url: '...' }`, `member: { login: 'operator' }`.
5. Invoke `Shipit::Webhooks::Handlers::MembershipHandler.new(payload).call` (simulating that `verify_signature` already passed using `attacker-org`'s own secret, as it is a separate controller-level concern).
6. Assert: `assert_not Membership.exists?(team: victim_team, user: legit_user)` — proving the membership was deleted despite the request being verified for `attacker-org`, not `victim-org`, demonstrating `repository_owner(attacker-org) != team.organization(victim-org)` yet the deletion still occurred.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L24-24)
```ruby
          member = User.find_or_create_by_login!(params.member.login)
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L29-30)
```ruby
          when 'removed'
            team.members.delete(member)
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
