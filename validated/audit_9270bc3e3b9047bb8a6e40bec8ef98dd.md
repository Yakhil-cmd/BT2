### Title
Cross-organization Team hijack via `github_id`-only lookup enabling `Shipit.github_teams` escalation - (`app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` looks up an existing `Team` solely by `github_id`, never checking that the record's `organization`/`slug` match the payload's `organization.login`. Because signature verification (`Shipit::WebhooksController#verify_signature`) authenticates a webhook only against the org named in that same payload's `organization.login` field, an admin of any second org onboarded onto a shared Shipit instance can send a genuinely-signed membership webhook whose attacker-chosen `team.id` collides with a previously created privileged team from a different org, silently reusing that `Team` row and adding themselves as a member of it.

### Finding Description
The broken binding: for a given `Team` row, `team.github_id == params.team.id` is treated as sufficient identity, when the real invariant that must hold is `team.organization == params.organization.login && team.github_id == params.team.id` (enforced only at DB level as `unique_index(["organization","slug"])`, not on `github_id` combined with organization).

Code path:
- `Shipit::WebhooksController#create` parses the raw JSON body and dispatches to handlers keyed by `X-Github-Event` [1](#0-0) .
- `verify_signature` resolves the signing secret using `repository_owner`, which for a `membership` event falls back to `params.dig('organization','login')` — i.e., the *same attacker-supplied field* that will later become `team.organization` [2](#0-1) . This means the org used to select the trusted webhook secret is always self-consistent with the payload's own `organization.login`, so an attacker who legitimately administers two different onboarded orgs (org-a, org-b) can produce two independently, correctly-signed webhooks — one per org's own secret.
- `MembershipHandler#find_or_create_team!` then does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` [3](#0-2) . Since `find_or_create_by!` matches purely on `github_id`, once a `Team` row exists for `github_id = X` from org-a, a second, differently-signed webhook from org-b carrying the same `team.id = X` will find and reuse that exact row (not create a new one), and org-a's `organization`/`slug` are left untouched.
- `MembershipHandler#process` then calls `team.add_member(member)` for the `'added'` action [4](#0-3) , appending the org-b user as a member of what is still recorded as org-a's team.
- If org-a's team is one of `Shipit.github_teams`, the injected org-b user now satisfies `User#authorized?`, which checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [5](#0-4)  — granting Shipit-wide authorization without ever being a real member of org-a's GitHub team.

Why existing guards fail: `verify_signature` only proves the payload was signed with *some* org's registered secret; it does not, and cannot, validate that the payload's `team.id` corresponds to a real GitHub team belonging to that org, because the JSON body itself is attacker-authored (not fetched live from GitHub) and `team.id` is an arbitrary attacker-chosen integer in the request. There is no application-level check tying `github_id` to a specific `organization`, and the DB unique index is on `(organization, slug)`, which does not protect `github_id` collisions across organizations.

### Impact Explanation
An attacker who legitimately controls the webhook configuration for at least one org onboarded to a shared/multi-tenant Shipit instance can forge a `membership` webhook naming any `team.id` they can guess or discover (e.g., a small sequential GitHub team ID, or one disclosed via prior legitimate events/logs), causing their chosen GitHub login to be silently added as a `member` of that `Team` row in Shipit's database. If that team is configured in `Shipit.github_teams`, the attacker (or any login they name) gains `User#authorized?` == true, i.e., full Shipit deploy/admin authorization — matching the "High: escalation into `Shipit.github_teams` authorization" category. The attack is repeatable for any team ID and any member login, and is not limited to a single stack — it grants global authorization within the Shipit instance.

### Likelihood Explanation
Preconditions are non-trivial but realistic for shared/multi-tenant deployments: the attacker must be an admin/owner of at least one GitHub organization that is already configured in Shipit's per-org GitHub settings (with a known webhook secret, since they set up that org's webhook themselves) and must know or guess the target's real `github_id` for a privileged team. Given GitHub team IDs are not secret and are visible via the GitHub API/UI to anyone who can see the target org's teams (or leaked via prior Shipit webhook logs), this is a low-cost reconnaissance step. No possession of Shipit's `secret_key_base`, `api_clients_secret`, or the *target* org's webhook secret is required — only the attacker's own (already-controlled) org's secret.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization`, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and raise/reject if a `Team` with that `github_id` already exists under a different `organization` (indicating either a real GitHub team ID reuse across renamed orgs or a forged payload). Add a DB-level unique index on `github_id` scoped appropriately, and add a model validation that rejects updates changing `organization` on an existing `github_id`.

### Proof of Concept
Minitest plan (`test/models/webhooks/membership_handler_test.rb` or similar):
1. Post a `membership` webhook (`action: 'added'`) with `team: { id: 42, name: 'A', slug: 'team-a', url: '...' }`, `organization: { login: 'org-a' }`, `member: { login: 'attacker' }`, signed with org-a's configured secret.
2. Assert one `Team` row exists with `github_id: 42, organization: 'org-a'`, and `attacker` is a member.
3. Post a second `membership` webhook with the same `team.id: 42`, but `organization: { login: 'org-b' }`, `member: { login: 'victim' }`, signed with org-b's configured secret.
4. Assert: `Team.where(github_id: 42).count == 1` (no new row created), the single row's `organization` is still `'org-a'` (unchanged), and `Team.find_by(github_id: 42).members.pluck(:login)` now includes `'victim'` — demonstrating an org-b actor was injected into org-a's team.
5. If `Shipit.github_teams` includes that team, additionally assert `User.find_by(login: 'victim').authorized?` is `true`, proving unauthorized escalation.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
