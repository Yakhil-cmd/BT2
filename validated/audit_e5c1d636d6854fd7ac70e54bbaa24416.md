### Title
Cross-organization team membership forgery via unscoped `Team.find_or_create_by!(github_id:)` in `MembershipHandler#process` — ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` only proves that the request body was signed by *some* organization's own `webhook_secret`, and `#repository_owner` falls back to `params.dig('organization','login')` when the `repository` key is absent (true for `membership` events). `MembershipHandler#find_or_create_team!` then looks up the target `Team` solely by `github_id`, with no check that the team's `organization` matches the organization whose secret verified the webhook, allowing an attacker who owns any registered org (with any `webhook_secret`) to add an arbitrary GitHub login as a member of a pre-existing `Team` belonging to a completely different, more privileged organization — including a team listed in `Shipit.github_teams`.

### Finding Description
Broken binding (should hold, does not): `Team#organization` (the org that owns the team record being mutated) `==` the organization whose `webhook_secret` verified the incoming request (i.e., `repository_owner`'s resolved `GitHubApp`).

Trace:
- `Shipit::WebhooksController#verify_signature` resolves `github_app = Shipit.github(organization: repository_owner)` and verifies `X-Hub-Signature` against that org's `webhook_secret` only [1](#0-0) .
- `#repository_owner` falls back to `params.dig('organization', 'login')` when no `repository` key is present, which is exactly the case for `membership` events [2](#0-1) .
- The attacker signs the payload with their own low-privilege org's secret, so `verify_webhook_signature` trivially succeeds since it only checks the signature against the org resolved from the payload itself [3](#0-2) .
- `MembershipHandler#find_or_create_team!` looks the team up **only by `github_id`**, with zero organization scoping: `Team.find_or_create_by!(github_id: params.team.id) { |team| team.github_team = params.team; team.organization = params.organization.login }` [4](#0-3) . The `organization =` assignment inside the block only executes on a *new* record; if a `Team` row with that `github_id` already exists (e.g., a legitimate, privileged team synced previously via `lib/tasks/teams.rake` or a prior legitimate webhook), the block is skipped entirely and the existing record — owned by a different organization — is returned unmodified.
- `#process` then unconditionally calls `team.add_member(member)` on whatever `Team` was found, using `member.login` fully attacker-controlled from the payload [5](#0-4) [6](#0-5) .
- Membership in a team listed in `Shipit.github_teams` directly satisfies `User#authorized?`: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) .

No existing guard closes this gap: `verify_signature` only authenticates "who sent this body," never "does the entity referenced inside the body belong to the sender." `ExplicitParameters` (`params do requires :team do requires :id, Integer ... end end`) only validates types/presence, not organizational ownership [8](#0-7) . `drop_unhandled_event` and `check_if_ping` are irrelevant to this path.

Attacker request: `POST /webhooks` with `X-Github-Event: membership`, body `{"action":"added","team":{"id":<target_privileged_team_github_id>,"name":"x","slug":"x","url":"x"},"organization":{"login":"attacker-org"},"member":{"login":"attacker-github-login"}}`, signed with `attacker-org`'s own registered `webhook_secret`.

### Impact Explanation
A successful request adds an arbitrary GitHub login (chosen by the attacker) as a member of any pre-existing `Team` record identified purely by its numeric `github_id`, regardless of which organization actually owns that team. If the targeted `github_id` corresponds to a team enumerated in `Shipit.github_teams`, the added user (which could be an account the attacker controls, or the attacker's own login) becomes `authorized?` for the whole Shipit instance, gaining access to protected stacks/deploys/rollbacks — a direct escalation into `Shipit.github_teams` authorization (matches the "High" impact category defined in the rules). The attack is repeatable against any team `github_id`, is not scoped to any single repository, and only requires the attacker to control one low-privileged registered organization and to know/guess the target team's numeric `github_id` (GitHub team IDs are often discoverable via the public GitHub API for teams the attacker can view, or via GitHub org membership listings).

### Likelihood Explanation
Preconditions: attacker must have a registered organization in Shipit's GitHub app configuration with any `webhook_secret` (stated as a given precondition, and plausible for any onboarded low-privilege org), must know the numeric `github_id` of a target privileged team (not secret, discoverable via GitHub's team APIs for teams visible to any member/collaborator, or brute-forceable since GitHub team IDs are sequential integers), and the target `Team` row must already exist in Shipit's database (true for any team synced via the standard team-sync flow, which is the normal operational state for teams referenced in `Shipit.github_teams`). No Shipit secrets, sessions, or API tokens are needed — full compliance with the stated attacker capability set. Cost is a single crafted HTTP POST.

### Recommendation
Scope the team lookup by both `github_id` AND the verified organization, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: repository_owner)` (passing the verified organization through to the handler), and reject the webhook (or raise) if an existing `Team` with that `github_id` has an `organization` different from the one that verified the signature, rather than silently mutating/using the mismatched record.

### Proof of Concept
Minitest plan (`ActionDispatch::IntegrationTest`, no live GitHub):
1. Configure two orgs in `Shipit.github_config`/`Shipit.github_teams`-relevant fixtures: `org_a` (attacker, low-privilege, `webhook_secret: "secret_a"`) and `org_b` (privileged, has a `Team` fixture with `github_id: 999`, `organization: "org_b"`, and this team's `id` included in `Shipit.github_teams`).
2. Build a membership webhook JSON body: `{"action":"added","team":{"id":999,"name":"x","slug":"x","url":"x"},"organization":{"login":"org_a"},"member":{"login":"attacker_login"}}` (no `repository` key).
3. Compute `X-Hub-Signature` using `org_a`'s `webhook_secret` (`"secret_a"`), HMAC-SHA1 over the raw body.
4. `post shipit_engine.webhooks_path, params: body, headers: {"X-Github-Event" => "membership", "X-Hub-Signature" => signature, "Content-Type" => "application/json"}`.
5. Assert `response.status == 200` (request accepted, not `422`).
6. Assert `Shipit::User.find_by(login: "attacker_login").teams.exists?(id: org_b_team.id)` is `true` — proving a member was added to `org_b`'s privileged team using only `org_a`'s webhook secret, and that `Shipit::User.find_by(login: "attacker_login").authorized?` returns `true`, demonstrating unauthorized escalation into `Shipit.github_teams` authorization from an unrelated, unprivileged organization.

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
