### Title
Membership webhook handler trusts `params.team.id` across organizations, allowing any configured tenant org to delete another org's team memberships - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#process` looks up the `Team` to mutate solely by `params.team.id` (the GitHub numeric team id) and never checks that `params.organization.login` — the organization whose secret validated the webhook signature — actually matches the found `Team#organization`. In a multi-tenant Shipit deployment (multiple GitHub orgs configured, as shown in `test/dummy/config/secrets_double_github_app.yml`), any org onboarded to the same Shipit instance can forge a self-signed `membership` webhook naming a foreign team's `github_id` and delete a real, privileged user's `Membership` in that foreign team.

### Finding Description
The broken binding: the organization that authenticates the request, `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` used in `Shipit::WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30,59-62`), is never required to equal `team.organization` — the tenant whose `Membership` row actually gets mutated in `MembershipHandler#process`.

Code path:
1. `WebhooksController#verify_signature` computes `repository_owner` from the attacker-controlled payload and calls `Shipit.github(organization: repository_owner)`, then verifies the HMAC signature using that organization's own `webhook_secret`. [1](#0-0) [2](#0-1) 
2. Because the attacker legitimately owns "attacker-org" (a separately configured tenant in Shipit's multi-org `github:` config), they can set `organization.login = "attacker-org"` in the payload and sign it with their own real `webhook_secret`. Verification passes cleanly - it is not forged, it is self-signed and valid for "attacker-org".
3. `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)`. If the attacker sets `team.id` to the victim's `Team#github_id` (a public GitHub team numeric id), the existing victim `Team` row (`organization: 'shopify'`) is *found*, not created, so the `organization:`-setting block never runs and is never checked against the found record. [3](#0-2) 
4. `member = User.find_or_create_by_login!(params.member.login)` resolves to the real, privileged victim user by login (assumed public knowledge per the question).
5. With `params.action == 'removed'`, `team.members.delete(member)` destroys the `Membership` row binding that user to the victim `Team`, even though the request was authenticated only against "attacker-org"'s secret, not "shopify"'s. [4](#0-3) 

No other guard closes this gap: `verify_signature` only checks the signature matches *some* organization's secret derived from attacker-supplied payload fields, and `drop_unhandled_event`/`ExplicitParameters` schema (`requires :organization { requires :login }`) only validate presence/type, not that it matches the mutated `Team#organization`. [5](#0-4) 

### Impact Explanation
An attacker who controls any single organization configured as a Shipit tenant (i.e., has a valid `webhook_secret` for their own org) can strip an arbitrary team membership belonging to a *different* tenant/org by referencing that team's known GitHub numeric id. Since `Shipit.github_teams` derives authorization from `Team`/`Membership` records, this is a cross-tenant escalation/deauthorization primitive: a privileged operator in org "shopify" can be silently removed from their team, and thus lose Shipit permissions, from a request that only proves control of an unrelated org "attacker-org". This is repeatable against any team whose `github_id` is known and matches the Critical category of "a payload for one repository/organization mutating another's team".

### Likelihood Explanation
This requires: (1) a multi-tenant Shipit deployment with at least two independently configured GitHub orgs (a documented, supported configuration per `docs/setup.md` "Using Multiple Github Applications"), (2) attacker control of one of those tenant orgs (able to generate a valid signature with their own `webhook_secret` — no Shipit secrets needed), and (3) knowledge of the victim team's numeric GitHub `id` and the victim member's `login` (both are treated as "known publicly" per the question's precondition and are often discoverable via GitHub's public API/UI). Attacker cost is a single crafted HTTP POST; the action is trivially repeatable against any team/user pair whose `github_id`/`login` is known.

### Recommendation
In `MembershipHandler#find_or_create_team!`/`#process`, verify that `params.organization.login` matches the found `Team#organization` before allowing `add_member`/`delete` to proceed (e.g., raise/drop the event if `team.organization != params.organization.login`), rather than trusting `github_id` alone to select the team to mutate.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`-style, no live GitHub):
1. Configure two orgs in test secrets (mirroring `test/dummy/config/secrets_double_github_app.yml`): `OrgOne` (victim, e.g. `shopify`) and `OrgTwo` (attacker), each with its own `webhook_secret`.
2. Create fixtures: `Team` with `organization: 'shopify'`, `github_id: 999`; a `User` with `login: 'victim_admin'`; a `Membership` linking them.
3. Build a `membership` webhook payload: `{ action: 'removed', team: { id: 999, name: 'x', slug: 'x', url: 'x' }, organization: { login: 'OrgTwo' }, member: { login: 'victim_admin' } }`.
4. Compute `X-Hub-Signature` using `OrgTwo`'s `webhook_secret` (attacker-controlled, legitimately known to them) via `OpenSSL::HMAC.hexdigest('sha1', org_two_secret, payload_json)`.
5. POST to `/webhooks` with `X-Github-Event: membership` and the computed signature.
6. Assert:
   - `assert_response :ok` (signature verification succeeds for `OrgTwo`).
   - `assert_difference -> { Shipit::Membership.count }, -1` — the victim's `shopify` team membership row is deleted.
   - Assert the equality that should have blocked this: `team.reload.organization == 'shopify'` while the authenticating org was `'OrgTwo'` — i.e. `payload_verifying_org != team.organization`, proving the cross-tenant write.

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
