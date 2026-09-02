This confirms the vulnerability chain. `Team.find_or_create_by!(github_id: params.team.id)` in `find_or_create_team!` is keyed purely on `github_id`, with the `organization` assignment only happening inside the block that runs on creation, not on find. Combined with `WebhooksController#verify_signature` resolving the GitHub App via `repository_owner`, which for `membership` events falls back to `params.dig('organization', 'login')` (the attacker's own org), the signature check validates correctly against the attacker's own legitimate webhook secret while the mutated `Team` record can belong to a different organization already in the database.### Title
Cross-organization webhook forgery escalates attacker into `Shipit.github_teams` authorization via `MembershipHandler#find_or_create_team!` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a request using `repository_owner`, which for `membership` events falls back to `params.dig('organization', 'login')` — the organization named inside the attacker-controlled payload itself. `MembershipHandler#find_or_create_team!` then looks up the `Team` to mutate purely by `github_id`, ignoring the organization that authenticated the request, so a legitimately signed webhook from `attacker-org` can add an attacker-controlled user as a member of a pre-existing `victim-org` `Team` row.

### Finding Description
The broken binding: the organization that authenticated the webhook (`Shipit.github(organization: repository_owner)` in `app/controllers/shipit/webhooks_controller.rb:25`, where `repository_owner == params.dig('organization', 'login')` per `app/controllers/shipit/webhooks_controller.rb:59-62`) must equal the organization owning the `Team` record being mutated (`Team#organization`). These are never checked against each other.

Path:
1. Attacker POSTs `/webhooks` with `X-Github-Event: membership`, a signature computed with `attacker-org`'s real `webhook_secret`, and body `{action:'added', team:{id: X, ...}, organization:{login:'attacker-org'}, member:{login:'attacker-login'}}`, where `X` is the `github_id` of a `Team` row already persisted for `victim-org`.
2. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` as `'attacker-org'` (no `repository` key in a membership payload, so it falls back to `organization.login`), fetches `Shipit.github(organization: 'attacker-org')`, and verifies the signature — which succeeds legitimately, since it is attacker-org's own real secret over attacker-org's own payload.
3. `MembershipHandler#process` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`) calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` (`membership_handler.rb:38-43`). Since a `Team` row with `github_id == X` already exists (from a legitimate prior sync for `victim-org`), `find_or_create_by!` returns that existing record — the block that would set `team.organization = params.organization.login` never runs, but the returned team object is still `victim-org`'s privileged team.
4. `team.add_member(User.find_or_create_by_login!('attacker-login'))` (`app/models/shipit/team.rb:41-43`) creates a `Membership` linking the attacker's new `User` row to the `victim-org` team.
5. `User#authorized?` (`app/models/shipit/user.rb:80-82`) checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?`; if the affected `Team` is configured in `Shipit.github_teams`, the attacker's user becomes globally authorized.

No existing guard prevents this: `verify_signature` only proves the payload came from *an* organization that legitimately controls its own webhook secret — it never re-validates that the `team`/`organization` referenced inside the payload's *body* matches the org that signed it. `find_or_create_by!(github_id:)` has no organization-scoping condition, so an existing cross-org row is silently reused and mutated.

### Impact Explanation
This is a genuine authentication/authorization-binding bypass: a webhook signed and authenticated under one organization's identity is used to mutate a `Team`/`Membership` belonging to a different, unrelated organization. Any attacker who legitimately administers *any* GitHub organization configured in Shipit's multi-org setup can, by simply learning the numeric `github_id` of a privileged team belonging to a different tenant (public GitHub API data), inject arbitrary GitHub logins into that team's membership in Shipit, and if that team is listed in `Shipit.github_teams`, gain `User#authorized?` system-wide. This is repeatable against any known `github_id` and any number of attacker-controlled GitHub logins, matching the "High - escalation into `Shipit.github_teams` authorization" (and arguably "Critical" given it can grant broad deploy authorization) impact category.

### Likelihood Explanation
Requires a multi-org Shipit deployment (documented, supported feature) where the attacker legitimately owns/administers one of the configured GitHub Apps/orgs — a low-cost, entirely self-service precondition (attacker just registers/administers their own org's GitHub App per `docs/setup.md`). The attacker must also know the numeric `github_id` of an existing privileged team, which is discoverable via GitHub's public team/org APIs. No Shipit secrets, sessions, or privileged roles are needed. The attack is a single crafted HTTP POST with a signature computed from the attacker's own legitimately-issued secret — fully reproducible and repeatable.

### Recommendation
In `find_or_create_team!`, scope the lookup by both `github_id` and the authenticating organization, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and reject/raise if a `Team` with that `github_id` already exists under a *different* `organization` (to prevent silent takeover/renaming of another org's team). Additionally, `WebhooksController#verify_signature` should not trust `params.dig('organization', 'login')` as authoritative without cross-checking it against the resource actually being mutated by the handler.

### Proof of Concept
Minitest (`test/controllers/webhooks_controller_test.rb`-style, using existing signing helpers already present in the repo's webhook controller tests):
1. Create `Team.create!(github_id: 4242, organization: 'victim-org', slug: 'victim-team', name: 'Victim Team', api_url: '...')`.
2. Stub `Shipit.github(organization: 'attacker-org')` to return a `GitHubApp` configured with a known `webhook_secret` ("attacker-secret").
3. Build payload `{action: 'added', team: {id: 4242, name: 'Victim Team', slug: 'victim-team', url: '...'}, organization: {login: 'attacker-org'}, member: {login: 'attacker-login'}}.to_json`.
4. Compute `X-Hub-Signature` as `"sha1=" + OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', payload)`.
5. POST to `/webhooks` with `X-Github-Event: membership` and the computed signature header.
6. Assert response is `200`.
7. Assert equality-before: `Shipit::Team.find_by(github_id: 4242).organization == 'victim-org'` (unchanged).
8. Assert `Shipit::Membership.exists?(user: Shipit::User.find_by(login: 'attacker-login'), team: Shipit::Team.find_by(github_id: 4242))` is `true`.
9. With `Shipit.stubs(:github_teams).returns([Shipit::Team.find_by(github_id: 4242)])`, assert `Shipit::User.find_by(login: 'attacker-login').authorized?` is `true`, demonstrating the organization that signed the request (`attacker-org`) differs from the organization whose team/authorization state was mutated (`victim-org`). [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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
