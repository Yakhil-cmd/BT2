## Analysis

**Binding claimed to break:** `organization_that_signed_webhook == organization_owning_mutated_team_row`, i.e. `Shipit.github(organization: repository_owner).webhook_secret` (attacker-org's secret) should equal the webhook_secret that authenticates writes to `shipit_teams` rows whose `organization` column is `'shopify'`.

**Tracing the path:**

- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner)` to verify the HMAC signature. [1](#0-0) [2](#0-1)  For a `membership` payload there is no `repository` key, so `repository_owner` resolves to `params['organization']['login']`, i.e. `'attacker-org'`. Signature verification therefore only proves the request came from `attacker-org`'s legitimate webhook, using `attacker-org`'s own `webhook_secret` — nothing here binds the payload to the organization that actually owns the `team.id` being referenced.
- `MembershipHandler#find_or_create_team!` calls `Team.find_or_create_by!(github_id: params.team.id)`, keyed **solely on `github_id`**, not on `params.organization.login`. [3](#0-2)  If a `Team` row with that `github_id` already exists (e.g. `shopify/developers`, created earlier via `Team.find_or_create_by_handle`), `find_or_create_by!` returns the **existing** record and the block (which would set `team.organization = params.organization.login`) is **never executed** because `find_or_create_by!` only runs the initializer block on creation, not on lookup. So the existing team's `organization` column remains `'shopify'` — it is not overwritten to `'attacker-org'`.
- `MembershipHandler#process` then does `team.add_member(User.find_or_create_by_login!(params.member.login))`, adding attacker's user to the **existing shopify team**, regardless that the signature validated against `attacker-org`. [4](#0-3) 
- `Team#add_member` appends the membership row. [5](#0-4) 
- `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?`. [6](#0-5)  If the `shopify/developers` `Team` id is in `Shipit.github_teams`, attacker's user now satisfies this check and becomes `authorized?`.

**Why this is a real bug:** signature verification is keyed by `repository_owner`/`organization.login` from the payload, which the attacker fully controls to be their own org, while the row being mutated (`Team.find_or_create_by!(github_id: ...)`) is keyed independently by an ID that has no relationship to which org's secret validated the request. There is no check anywhere in `MembershipHandler` (nor in `WebhooksController`) that `params.organization.login` matches the existing `team.organization` before mutating membership. This satisfies the "escalation into `Shipit.github_teams` authorization" impact category, and is squarely within `app/models/shipit/webhooks/handlers/membership_handler.rb`, not excluded by the out-of-scope list.

I was not able to independently verify `Shipit.github_teams`'s exact implementation body (only found references via grep, not the method body), but the `User#authorized?` reference to `Shipit.github_teams.map(&:id)` confirms it returns `Team` records/ids configured as authorization gates, consistent with the described precondition.

### Title
Membership webhook signed by any GitHub organization can grant its members access to any pre-existing `Shipit.github_teams` team by reusing a known `github_id` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` looks up teams solely by `github_id`, ignoring the `organization` field in the payload, while `WebhooksController#verify_signature` only proves the webhook was validly signed by *some* organization's own webhook secret — not necessarily the organization owning the referenced team. An attacker who owns a GitHub organization with its own webhook secret can send a `membership` event referencing the `github_id` of an already-existing team (e.g. a Shipit-authorizing team), causing themselves to be added as a member of that team.

### Finding Description
The broken binding: `organization_that_signed_request` (`attacker-org`, verified via `Shipit.github(organization: repository_owner).verify_webhook_signature`) must equal `organization_owning_team_row` (`shopify`, the `organization` column on the pre-existing `Team` row with the given `github_id`) for the mutation to be authorized — but it does not have to, because `Team.find_or_create_by!(github_id: params.team.id)` finds the record purely by `github_id` and the block that would set `team.organization` only executes on record creation, never on lookup of an existing record. [3](#0-2)  `WebhooksController#repository_owner` derives from `params.dig('organization','login')` for events without a `repository` key [2](#0-1) , and `verify_signature` uses that value to pick which `GitHubApp`/secret to verify against [1](#0-0) , so a payload with `organization.login = 'attacker-org'` signed with attacker-org's real secret passes verification cleanly — no `GithubOrganizationUnknown` exception, no rejection. `MembershipHandler#process` then unconditionally calls `team.add_member(member)` on the found team object [4](#0-3) , appending the membership without ever comparing `params.organization.login` to `team.organization`.

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: membership`, body `{action: 'added', team: {id: <shopify team's github_id>, ...}, organization: {login: 'attacker-org'}, member: {login: 'attacker'}}` signed with `attacker-org`'s real webhook secret. Verification succeeds against `attacker-org`. `find_or_create_team!` finds the pre-existing `shopify` team by `github_id` and returns it unchanged. `attacker` user is created/found and appended to `team.members`.

Existing guards do not catch this: `verify_signature` only checks the HMAC against the org derived from the payload itself, which the attacker controls; `drop_unhandled_event` does not apply since `membership` is a handled event; the `ExplicitParameters` schema on `MembershipHandler` validates shape, not organization ownership; there is no `require_permission!`/`force_github_authentication` in this webhook flow to catch the mismatch.

### Impact Explanation
Once the membership row exists, `User#authorized?` (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`) [6](#0-5)  returns true for the attacker's user if the targeted team is among `Shipit.github_teams`. This is an authentication/authorization bypass: the attacker's account gains authorized status across every `ShipitController`-derived controller, matching the "escalation into `Shipit.github_teams` authorization" High-severity category (and potentially enabling further actions like minting API tokens via `ApiClientsController`, pushing toward Critical). The attack is repeatable against any `Team` row whose `github_id` is known or guessable, and does not require compromising `shopify`'s or Shipit's own secrets — only attacker's own org's webhook secret, which they legitimately possess.

### Likelihood Explanation
Preconditions: (1) Shipit configured with multiple GitHub organizations (`Shipit.github_organizations`/per-org `webhook_secret`s) including both the victim org (e.g. `shopify`) and an org the attacker controls; (2) a `Team` row for the victim org already exists in the DB with a known/guessable `github_id`; (3) that team is part of `Shipit.github_teams`. Attacker cost is low: create/own a GitHub organization, install a minimal GitHub App or configure a webhook with a secret they control, and know (or guess) the target team's numeric GitHub `github_id`. This is feasible and repeatable per request.

### Recommendation
In `MembershipHandler#find_or_create_team!`, require that `params.organization.login` matches the existing `team.organization` (case-insensitively) before proceeding, and reject/raise if they diverge instead of silently returning the existing record. Alternatively, scope the lookup with `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)` so a mismatched organization creates a *new* team row rather than reusing/mutating membership of an existing one from a different organization.

### Proof of Concept
minitest plan (webhooks_controller_test.rb or membership_handler test):
1. Create `shopify_team = shipit_teams(:shopify_developers)` (or equivalent fixture) with `organization: 'shopify'`, `github_id: 555`, and add it to `Shipit.github_teams` stub.
2. Configure `Shipit.github(organization: 'attacker-org')` with a distinct `webhook_secret` (test double / secrets stub).
3. Build payload: `{action: 'added', team: {id: 555, name: 'Developers', slug: 'developers', url: '...'}, organization: {login: 'attacker-org'}, member: {login: 'attacker'}}`, compute `X-Hub-Signature` using attacker-org's webhook secret.
4. `post :create` with `X-Github-Event: membership` and that signature/body; assert `response.status == 200`.
5. Assert `User.find_by(login: 'attacker').in?(shopify_team.reload.members)` is `true`.
6. Assert `User.find_by(login: 'attacker').authorized?` is `true`.
7. Before-fix assertion: both sides of the binding (`'attacker-org'` used to sign vs `'shopify'` on `shopify_team.organization`) diverge yet the write succeeds — proving the binding is not enforced.

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
