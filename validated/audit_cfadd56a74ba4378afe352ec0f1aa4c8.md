### Title
Membership webhook trusts `team.id` alone to select the `Team` row, letting a valid signature from any org add members to a privileged `Shipit.github_teams` team - (File: app/models/shipit/team.rb, app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` looks up a `Team` solely by `github_id` (`params.team.id`), never checking that `params.organization.login` matches the existing team's `organization`. Because `Team#add_member` (`members.append(member) unless members.include?(member)`) is then called unconditionally on whatever `Team` row was returned, a webhook that is fully and correctly signed for the attacker's own GitHub organization can still mutate a `Team` belonging to a different organization, provided the attacker can get GitHub to hand out a `team.id` that collides with an existing privileged team's `github_id`.

### Finding Description
The broken binding is: `team.organization == params.organization.login` should hold whenever `team = find_or_create_team!` is used to authorize a write, but the code never enforces it.

Path:
- `WebhooksController#verify_signature` picks the GitHub App/secret to verify against using `repository_owner`, which for membership events falls back to `params.dig('organization','login')` [1](#0-0) . This means the signature only proves the payload was signed by *the attacker's own organization's* webhook secret — it says nothing about which `team.id` may be referenced inside the payload.
- `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` — keyed purely on the attacker-supplied integer `team.id`, with no comparison to the team's existing `organization` field [2](#0-1) . If a `Team` row with that `github_id` already exists (e.g., one of the org teams resolved into `Shipit.github_teams` at boot via `Team.find_or_create_by_handle`, see `lib/shipit.rb` `github_teams` method), `find_or_create_by!` returns that existing row untouched, regardless of which organization sent the webhook.
- `Team#add_member` then unconditionally appends the membership: `members.append(member) unless members.include?(member)` [3](#0-2) .
- `User#authorized?` grants access based on membership in `Shipit.github_teams` by local `Team#id`: `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [4](#0-3) , so any user injected into that team gains authorization.

GitHub team ids are global/sequential and not namespaced by organization, so an attacker who fully controls their own org (real webhook secret, real signed events) can create and delete teams in their org to enumerate ids until one lands on the `github_id` of a real `Shipit.github_teams` team belonging to a different org, then send an `added` membership event naming that id together with any `member.login` they choose. `MembershipHandler` never checks `params.organization.login` against the resolved `team.organization`, so the membership is written into the privileged team.

None of the existing guards catch this: `verify_signature` validates HMAC per-organization but is organization-scoped to the attacker's own org for membership events; the `ExplicitParameters` schema in `MembershipHandler` only validates types/presence of `team.id`, `organization.login`, `member.login`, not their mutual consistency; there is no `require_permission!`/`stacks` scope check on this webhook path.

### Impact Explanation
A successful collision lets the attacker have an arbitrary GitHub login (including their own) added as a `Membership` of a `Team` listed in `Shipit.github_teams`, which is exactly the model used to gate `User#authorized?`. This is a cross-tenant authorization write: a payload legitimately signed for organization A mutates a `Team` record that conceptually belongs to organization B. This matches the High severity category "escalation into `Shipit.github_teams` authorization." The attack is repeatable per discovered id and, once membership exists, persists until manually removed (a `removed` webhook from the attacker's own org — again keyed only by `github_id` — could also be used to *remove* other people from that privileged team).

### Likelihood Explanation
The attacker needs: (1) a GitHub organization they control with a valid Shipit webhook secret configured (a normal, low-privilege precondition many self-service Shipit deployments allow), (2) the ability to create/delete teams in their own org to explore `team.id` values, and (3) knowledge/guessing of a target `github_id` belonging to a `Shipit.github_teams` team in another org. GitHub team ids are sequential and global, so with enough churn (creating/deleting many teams) an attacker can iterate a contiguous range of ids economically; this is a brute-force/guessing exercise rather than a cryptographic break, but it requires no forged signature and no leaked secret — only patience and control of one org. This is a real, low-cost path once the organizational precondition (having a legitimate org with a configured Shipit webhook) is met.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization` (e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and additionally verify that any existing `Team` matched by `github_id` actually belongs to `params.organization.login` before calling `add_member`/`members.delete`; raise/drop the event if the organization does not match the team's recorded organization.

### Proof of Concept
minitest plan (`test/models/team_test.rb` or a new webhook handler test):
1. Fixture setup: `team_a = Team.create!(github_id: 999, organization: 'victim-org', slug: 'admins', name: 'Admins', api_url: '...')`; stub `Shipit.github_teams` to return `[team_a]`.
2. Build a membership payload with `team: { id: 999, name: 'Admins', slug: 'admins', url: '...' }`, `organization: { login: 'attacker-org' }`, `member: { login: 'mallory' }`, `action: 'added'`.
3. Call `Shipit::Webhooks::Handlers::MembershipHandler.call(payload)` directly (bypassing HTTP signature layer, as it is legitimately signed for `attacker-org` in the real exploit — only `MembershipHandler`'s own logic is under test).
4. Assert: `team_a.reload.members.map(&:login)` includes `'mallory'`, i.e. `team_a.organization` (`'victim-org'`) != `payload['organization']['login']` (`'attacker-org'`) yet the membership was created — proving the equality `team.organization == params.organization.login` is not enforced.
5. Assert `User.find_by(login: 'mallory').authorized?` becomes `true` given the `Shipit.github_teams` stub, demonstrating the authorization escalation.

### Citations

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
