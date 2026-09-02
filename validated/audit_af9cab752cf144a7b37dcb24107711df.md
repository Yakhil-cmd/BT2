### Title
Membership webhook signature is verified against the attacker-supplied `organization.login`, while `Team` lookup keys only on `team.id` — allowing a payload verified under one org to mutate a `Team` bound to a different org - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to check against using `repository_owner`, which for `membership` events resolves to `params.dig('organization','login')` — a value fully controlled by the request body. `MembershipHandler#find_or_create_team!` then looks up the target `Team` solely by `github_id` (`params.team.id`), ignoring whether the persisted `team.organization` matches the organization that was just used to verify the signature. This decouples "which org's secret authenticated the request" from "which org's Team gets mutated."

### Finding Description
The binding that should hold is:
`organization used to verify signature (repository_owner == params.organization.login submitted by attacker)` **==** `Team#organization for the Team row actually mutated (team.github_id == params.team.id)`.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` from the body itself (`params.dig('repository','owner','login') || params.dig('organization','login')`) [1](#0-0)  and fetches `Shipit.github(organization: repository_owner)` to verify the HMAC signature [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` trivially returns `true` when that organization has no configured `webhook_secret`: `return true unless webhook_secret` [3](#0-2) . Given the stated precondition that org-A has no `webhook_secret`, any signature (or none) passes for a payload whose `organization.login` is `org-A`.
3. `MembershipHandler#process` then calls `find_or_create_team!`, which resolves the `Team` strictly by `github_id: params.team.id` via `find_or_create_by!` [4](#0-3) . The block that assigns `team.organization = params.organization.login` only executes on **creation**; if a `Team` row with that `github_id` already exists (e.g., seeded/created earlier while legitimately bound to org-B), `find_or_create_by!` returns the existing record unchanged, and `params.organization.login` (org-A) is never checked against the persisted `team.organization` (org-B).
4. `process` proceeds to call `team.add_member(User.find_or_create_by_login!(params.member.login))` [5](#0-4) , and `Team#add_member` appends the member without any organization re-check [6](#0-5) .

Attacker request: POST `/webhooks` with header `X-Github-Event: membership`, body `{"action":"added","team":{"id":<org-B's known team github_id>,"name":"x","slug":"x","url":"x"},"organization":{"login":"org-A"},"member":{"login":"attacker-controlled-login"}}`. Because `organization.login` is `org-A` (no `webhook_secret` configured), `verify_signature` passes regardless of the actual `X-Hub-Signature` header. The handler then resolves the pre-existing `Team` belonging to org-B by `github_id` and adds the arbitrary member to it.

Existing guards do not stop this: `verify_signature` only checks that *some* valid (or optional) secret was presented for the org named in the body, it never cross-checks against the `Team`'s persisted `organization`; `ExplicitParameters` schema for `MembershipHandler` only validates presence/type of fields, not organization consistency [7](#0-6) ; `drop_unhandled_event` and `check_if_ping` are irrelevant to this path.

### Impact Explanation
A successful request appends an arbitrary GitHub login as a member of a `Team` record that is bound to a different organization (org-B) than the one whose (absent) secret validated the request. If that `Team` is one of the entries in `Shipit.github_teams`, the newly added `User` becomes `authorized?` for Shipit (`User#authorized?` checks membership in `Shipit.github_teams`) [8](#0-7) , granting cross-tenant authorization escalation without any legitimate GitHub org action. This matches the "escalation into `Shipit.github_teams` authorization" / cross-tenant write impact category, and is repeatable against any `Team` github_id the attacker can enumerate, for `removed` actions it can also strip legitimate members.

### Likelihood Explanation
Requires: (a) at least one other organization (org-A) configured in Shipit without a `webhook_secret` (or any org whose secret the attacker can otherwise satisfy) — a realistic multi-tenant misconfiguration since `webhook_secret` is optional per `GitHubApp#initialize` (`@webhook_secret = @config[:webhook_secret].presence`) [9](#0-8) ; (b) knowledge of the target `Team`'s numeric GitHub `id` (not a Shipit secret — obtainable via GitHub's team API/URLs). No Shipit session, API token, or GitHub secret is needed. Attacker cost is a single unauthenticated HTTP POST, fully repeatable.

### Recommendation
On every `membership` webhook, verify that `params.organization.login` matches the persisted `Team#organization` for the team resolved by `github_id`; if they diverge, reject the event (log and no-op) rather than mutating the existing team. Additionally, `find_or_create_team!` should scope the lookup by both `github_id` and `organization` (or re-validate `team.organization == params.organization.login` after fetch) before calling `add_member`/`members.delete`.

### Proof of Concept
```ruby
test "membership webhook cannot mutate a Team belonging to a different organization" do
  team_b = shipit_teams(:some_team) # or create!: organization: 'org-B', github_id: 4242
  team_b.update!(organization: 'org-B', github_id: 4242)

  payload = {
    action: 'added',
    team: { id: 4242, name: 'x', slug: 'x', url: 'https://x' },
    organization: { login: 'org-A' }, # org-A has no webhook_secret configured
    member: { login: 'attacker-login' }
  }.to_json

  # org-A has no webhook_secret -> verify_webhook_signature returns true unconditionally
  post shipit.webhooks_path, params: payload,
       headers: { 'X-Github-Event' => 'membership', 'CONTENT_TYPE' => 'application/json' }

  team_b.reload
  refute_includes team_b.members.map(&:login), 'attacker-login',
    "org-A's (no-secret) signature must not authorize mutation of team.organization == 'org-B'"
end
```
Before the fix this assertion fails (member is added); the equality `repository_owner (org-A) == team.organization (org-B)` is violated, confirming the cross-tenant write.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-28)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
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
