### Title
Cross-tenant `Team`/`Membership` write via unchecked organization binding in `find_or_create_team!` - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::MembershipHandler#find_or_create_team!` only sets `team.organization` inside the `find_or_create_by!` create block, so when the targeted `Team` row already exists it is returned unmodified regardless of whether the webhook's `organization.login` matches the row's stored `organization`. Combined with `WebhooksController#verify_signature` validating the HMAC against whichever organization's app config matches `repository_owner` (here `organization.login`, since membership payloads carry no `repository` object), an attacker who controls a webhook secret for *any* organization configured in the same Shipit instance can forge a `membership` event that mutates a `Team` belonging to a different organization.

### Finding Description
The binding that should hold is: `params.organization.login == team.organization` for the `Team` row identified by `github_id: params.team.id`, before `team.add_member(member)` is allowed to run.

Trace:
- `WebhooksController#create` parses JSON and dispatches to `Shipit::Webhooks.for_event(event)` [1](#0-0) .
- `verify_signature` resolves the GitHub App/secret to check against solely from `repository_owner`, which for a `membership` payload falls back to `params.dig('organization', 'login')` — a field fully controlled by the attacker's own request [2](#0-1) . It signs against whatever GitHub App config exists for that organization string, i.e. the attacker's own org config in a multi-org Shipit deployment.
- `MembershipHandler#process` calls `find_or_create_team!`, then unconditionally calls `team.add_member(member)` for `action == 'added'` [3](#0-2) .
- `find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` — the assignment only executes in the *create* block; when a `Team` with that `github_id` already exists, the existing record (with its original `organization`) is returned untouched [4](#0-3) .
- `Team#add_member` appends the member with no organization check at all [5](#0-4) .

Exploit flow: attacker POSTs to `/webhooks` with `X-Github-Event: membership`, `action: 'added'`, `team.id` = numeric `github_id` of a victim `Shipit::Team` (a team in `Shipit.github_teams`), `organization.login` = attacker's own configured org, `member.login: 'attacker'`, signed with the attacker's own org's `webhook_secret`. `verify_signature` passes because it validates only against the attacker's own org's app config, not the victim team's organization. `find_or_create_team!` finds the existing victim `Team` (create block skipped, no organization re-check), and `add_member` inserts a `Membership` linking `attacker` to that team — a write for one organization's data that was never authenticated by that organization's signature.

Existing guards do not close this gap: `verify_signature` authenticates that *some* organization signed the request, but never authenticates that the *specific team being mutated* belongs to that organization; the `ExplicitParameters` schema in `MembershipHandler` validates payload shape only, not cross-record ownership.

### Impact Explanation
A successful forged request adds an attacker-controlled `User` as a `Membership` of a `Team` that is part of `Shipit.github_teams`. If that team gates authorization (via `User#authorized?`/`force_github_authentication` checking `current_user.teams` against `Shipit.github_teams`), the attacker gains privileged access to the Shipit instance without ever having a real GitHub membership in that org — an authorization bypass into a security boundary the app is supposed to enforce, and a cross-tenant write (one org's webhook mutating another org's team data) in multi-org Shipit deployments. This is repeatable against any `Team` github_id known to the attacker and requires only one authenticated request per target team/member pair.

### Likelihood Explanation
This requires: (1) the Shipit instance configured for multiple GitHub organizations/apps (supported per `lib/shipit.rb`'s per-organization `github` lookup and documented multi-app secrets), (2) attacker legitimately controlling one of those configured organizations (and thus its `webhook_secret`) while not controlling the victim organization, and (3) attacker knowing the victim team's numeric `github_id` (discoverable via GitHub's public team/org APIs or observed webhook traffic). Given these preconditions, the attack is cheap (a single crafted HTTP POST) and fully repeatable.

### Recommendation
In `find_or_create_team!`, always verify (not just set-on-create) that `params.organization.login == team.organization` for pre-existing rows, and reject/raise (or use `Team.find_by(github_id:, organization:)`) rather than silently reusing a team from a different organization; e.g., raise `ArgumentError`/return 422 when an existing team's organization doesn't match the authenticated webhook's organization.

### Proof of Concept
Minitest plan (add to `test/controllers/webhooks_controller_test.rb`, no live GitHub):
1. Configure `secrets.github` with two orgs, `victim-org` (secret `S1`) and `attacker-org` (secret `S2`), mirroring `secrets_double_github_app.yml`.
2. Create `victim_team = Shipit::Team.create!(github_id: 999, organization: 'victim-org', slug: 'core', name: 'Core')`; stub `Shipit.github_teams` to include it.
3. Build membership payload: `{ action: 'added', team: { id: 999, name: 'Core', slug: 'core', url: '...' }, organization: { login: 'attacker-org' }, member: { login: 'attacker' } }`.
4. Sign the raw JSON with `S2` (attacker-org's secret) and set `X-Hub-Signature`/`X-Github-Event: membership`.
5. Assert before: `Shipit::Team.find_by(github_id: 999).organization == 'victim-org'`.
6. POST to `/webhooks`; assert `assert_response :ok`.
7. Assert after: `Shipit::Team.find_by(github_id: 999).organization == 'victim-org'` (unchanged) **yet** `Shipit::Membership.exists?(team_id: victim_team.id, user_id: Shipit::User.find_by(login: 'attacker').id)` is `true` — proving a `Membership` was written into `victim-org`'s team using only `attacker-org`'s signature.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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
