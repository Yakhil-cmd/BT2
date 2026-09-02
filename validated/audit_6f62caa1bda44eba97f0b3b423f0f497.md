### Title
Webhook signature check is a no-op when a tenant's `webhook_secret` is blank, and `MembershipHandler` never checks that the authenticated organization owns the target team - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` for the payload's `repository.owner.login`/`organization.login` and delegates verification to it, but `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that tenant's `webhook_secret` is blank. `MembershipHandler#process` then trusts `params.team.id` alone to locate/mutate a `Team`, never checking that `params.team`/`params.organization` actually belongs to the organization whose secret (or lack thereof) authenticated the request. This lets an attacker who controls a low-security tenant ("attacker-org" with no configured `webhook_secret`) forge a `membership` webhook that adds themselves to a `Team` belonging to a different, legitimately-secured tenant, as long as that team's `github_id`/`name`/`slug`/`url` are known.

### Finding Description
The broken binding, stated as an equality that should hold but does not:
`organization_that_authenticated_the_request` (`Shipit.github(organization: repository_owner)`, whose blank `webhook_secret` trivially "verifies" the payload) `== organization_that_owns_the_mutated_team` (the real owner of the pre-existing `Team` row matched by `github_id`).

Code path:
1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` (falls back to `organization.login`), both attacker-controlled and set to `'attacker-org'` in the payload. [1](#0-0) [2](#0-1) 
2. `Shipit.github(organization: 'attacker-org')` returns a `GitHubApp` configured with `@webhook_secret = @config[:webhook_secret].presence`, which is `nil` per the stated precondition (blank secret for that tenant). [3](#0-2) 
3. `verify_webhook_signature` short-circuits: `return true unless webhook_secret`, so any body/signature combination passes for this tenant. [4](#0-3) 
4. `MembershipHandler#process` → `find_or_create_team!` looks up the `Team` purely by `params.team.id` (the real, pre-existing GitHub team id belonging to a *different*, properly-secured organization) and, if found, does not touch `organization`/other identifying fields since `find_or_create_by!` only assigns them in the creation block, which is skipped when the record already exists. [5](#0-4) 
5. `team.add_member(member)` appends the attacker's freshly created `User` to that team's `members`. [6](#0-5) 
6. `User#authorized?` checks membership in any team whose id is in `Shipit.github_teams`, so if the targeted team is in that list, the attacker becomes authorized instance-wide. [7](#0-6) 

Why existing guards fail: `verify_signature` is scoped per-tenant by design (multi-tenant `secrets_double_github_app.yml` pattern), but it never re-validates that the `team`/`organization` payload fields are consistent with the tenant that was used for verification. `MembershipHandler`'s `ExplicitParameters` schema only validates types/presence, not organizational ownership, and `find_or_create_team!` has no check against the authenticating organization. [8](#0-7) 

### Impact Explanation
An attacker who controls any tenant configured in `Shipit.github_teams`'s host application with a blank `webhook_secret` can forge a `membership` webhook naming a genuine `Team` (identified by its real `github_id`) that belongs to a different, properly-secured organization, and add an arbitrary attacker-controlled `User` (created on demand via `User.find_or_create_by_login!`) to that team. If the targeted team is listed in `Shipit.github_teams`, this flips `User#authorized?` to `true` for that user across the entire Shipit instance, granting cross-tenant privilege escalation. This matches the "escalation into `Shipit.github_teams` authorization" High-severity category (and could be considered Critical since it is effectively an authentication/authorization bypass granting broad access). The attack is repeatable for any team whose `github_id`/`name`/`slug`/`url` the attacker can learn (e.g., via public GitHub team pages or API), and works across tenants since `Team` records are global (not scoped per-organization in the DB schema/lookup).

### Likelihood Explanation
Requires: (a) multi-tenant Shipit deployment with more than one `GitHubApp` configuration, (b) at least one configured tenant whose `webhook_secret` is left blank, and (c) attacker knowledge of a real GitHub team's `id`/`name`/`slug`/`url` for a team listed in `Shipit.github_teams`. Given these preconditions (explicitly stated as met in the question), the attacker's cost is a single unauthenticated HTTP POST to `/webhooks` with a crafted JSON body and the `X-Github-Event: membership` header — no secrets, tokens, or GitHub permissions are needed. The exploit is fully repeatable and requires no timing or race conditions.

### Recommendation
- Do not treat a blank/misconfigured `webhook_secret` as "verified" — fail closed (`return false unless webhook_secret`) in `GitHubApp#verify_webhook_signature`, or require every `GitHubApp` configuration to have a non-blank secret at boot time.
- In `MembershipHandler#find_or_create_team!` (and any other handler doing `find_or_create_by!` on GitHub-sourced identifiers), verify that `params.organization.login` matches the `organization` already stored on an existing `Team` record before mutating membership, rejecting the webhook otherwise.
- Scope the `repository_owner`/`organization_owner` used for signature verification against the resource being mutated, so a webhook authenticated under organization A can never write to a `Team`/`Stack`/`Commit` known to belong to organization B.

### Proof of Concept
Minitest controller test (would go in `test/controllers/webhooks_controller_test.rb`, out of scope to add per rules but described for reproducibility):
1. Seed a `Team` (`github_id: 555`, `organization: 'victim-org'`) and add its id to `Shipit.github_teams` (via stubbing `Shipit.github_teams`).
2. Stub `Shipit.github(organization: 'attacker-org')` to return a `GitHubApp` instance whose `webhook_secret` is `nil`.
3. POST to `/webhooks` with header `X-Github-Event: membership` and body:
   `{"action":"added","team":{"id":555,"name":"Victim Team","slug":"victim-team","url":"https://api.github.com/teams/555"},"organization":{"login":"attacker-org"},"member":{"login":"attacker"},"repository":{"owner":{"login":"attacker-org"}}}`
4. Assert response is `200 OK` (not `422`).
5. Assert: `Shipit::User.find_by(login: 'attacker').teams.exists?(github_id: 555)` is `true` — i.e. `Membership.exists?(user: attacker_user, team: victim_team)`.
6. Assert `attacker_user.authorized?` is now `true`, proving cross-tenant escalation into `Shipit.github_teams`.

Both sides of the equality diverge after the request: `organization_that_authenticated = 'attacker-org'` while `organization_that_owns_team_mutated = 'victim-org'`, confirming the broken binding.

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

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
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
