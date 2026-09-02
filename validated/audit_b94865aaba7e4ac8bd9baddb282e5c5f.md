### Title
Cross-organization Membership removal via `github_id`-only team lookup in `MembershipHandler#process` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#process` resolves the target `Team` solely by `params.team.id` (GitHub's numeric team id) via `find_or_create_team!`, without verifying that `params.organization.login` actually owns that team. Because `verify_signature` in `WebhooksController` only checks that the payload's signature matches the secret of the organization named in the payload itself (not that the payload's `team`/`member` actually belong to that organization), an attacker who controls a genuinely GitHub-registered org can send a validly-signed `membership` `removed` event naming any known team `github_id` and any victim `member.login`, causing that user's `Membership` row on the victim org's team to be deleted.

### Finding Description
The broken binding is:
`team.organization == params.organization.login` must hold before `team.members.delete(member)` executes.

Trace:
- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) computes `repository_owner` as `params.dig('repository','owner','login') || params.dig('organization','login')`. For a `membership` event there is no `repository` key, so `repository_owner` becomes `params['organization']['login']` — an attacker-controlled string. `Shipit.github(organization: repository_owner)` then looks up that org's registered GitHub App/webhook secret, and `verify_webhook_signature` validates the request's `X-Hub-Signature` against **that** organization's secret. If the attacker owns/administers a real GitHub org onboarded to Shipit, they can produce a validly-signed `membership` webhook where `organization.login` is their own org.
- `MembershipHandler#process` (app/models/shipit/webhooks/handlers/membership_handler.rb:22-34) then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { ... }` (lines 38-43). The lookup key is only `github_id` — the numeric GitHub team id, which is global across GitHub, not scoped to the org named in the payload. If a team with that `github_id` already exists in Shipit's DB (created earlier by the legitimate victim org's own `membership` webhooks), `find_or_create_by!` returns the **existing victim `Team` record**, and the create block (which would reset `organization`) is never invoked.
- `member = User.find_or_create_by_login!(params.member.login)` resolves (or creates) the victim user purely by GitHub login, again with no organization binding.
- For `action == 'removed'`, `team.members.delete(member)` (line 30) deletes the `Membership` row joining the victim team and victim user — regardless of the fact that the webhook was signed by, and named, an unrelated attacker-controlled organization.

None of the existing guards catch this: `verify_signature` proves *the sender knows the attacker org's secret*, not that the org owns the `team.id`/`member` referenced in the payload; `ExplicitParameters` schema only validates types/presence, not cross-field ownership; `drop_unhandled_event` is irrelevant; there's no `require_permission!`/`User#authorized?` check anywhere in this handler.

Exploit flow: attacker (who administers `evil-org`, onboarded to Shipit with its own webhook secret) sends `POST /webhooks` with header `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with `evil-org`'s secret, and body:
```json
{
  "action": "removed",
  "team": {"id": <victim_team_github_id>, "name": "...", "slug": "...", "url": "..."},
  "organization": {"login": "evil-org"},
  "member": {"login": "victim-user"}
}
```
This passes `verify_signature` (signed correctly for `evil-org`), then in `process`, `find_or_create_team!` resolves the existing victim `Team` by `github_id`, and `team.members.delete(member)` strips `victim-user`'s `Membership` from the victim org's privileged team.

### Impact Explanation
This is a cross-tenant mutation: a webhook genuinely signed by one organization (`evil-org`) can delete a `Membership` row belonging to a completely different, privileged organization's `Team`, deauthorizing a legitimate Shipit user (e.g. removing them from `Shipit.github_teams`-linked access, since `Team`/`Membership` back Shipit's team-based authorization) without that victim org's consent or any interaction from GitHub for the victim org. This matches the "High - escalation/deauthorization" category via unauthorized mutation of another organization's Team/Membership state, and is repeatable against any team whose numeric `github_id` the attacker can learn (team ids are visible via GitHub's public API/UI in many cases) and any known victim GitHub login.

### Likelihood Explanation
Preconditions: the attacker must control (or be an admin/owner of) at least one GitHub organization that is legitimately configured in Shipit with a `membership` webhook and a real webhook secret (i.e., `Shipit.github(organization: 'evil-org')` resolves to a valid app/secret) — this is achievable by any GitHub user who creates an org and has Shipit installed for it, or who is a member of an already-onboarded org with admin rights to trigger a real `membership` event. The attacker also needs the victim's numeric GitHub team `github_id` (discoverable via GitHub API endpoints for public teams, or previously observed) and the victim's GitHub login (public). No Shipit secrets, session, or API token are required — only ownership of a legitimately signed org. This is a low-cost, repeatable attack (one HTTP POST per removal) against any team ID already known to Shipit's DB.

### Recommendation
In `find_or_create_team!`, scope the lookup by both `github_id` and `organization` (e.g., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and in `MembershipHandler#process`, verify the resolved `team.organization == params.organization.login` before performing `add_member`/`members.delete`, raising/dropping the event otherwise. Additionally, `WebhooksController#verify_signature`'s `repository_owner` derivation should not be trusted as authorization that the *contents* of `team`/`member` belong to that org — the handler itself must enforce this invariant.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/membership_handler_test.rb`, hypothetical since none currently exists):
```ruby
test "removed action from an unrelated organization cannot delete a membership belonging to a different org's team" do
  victim_team = shipit_teams(:shipit) # or create!(organization: 'victim-org', github_id: 4242, ...)
  victim_user = shipit_users(:walrus)
  victim_team.add_member(victim_user)
  assert_difference -> { Shipit::Membership.count }, 0 do
    Shipit::Webhooks::Handlers::MembershipHandler.call(
      'action' => 'removed',
      'team' => { 'id' => victim_team.github_id, 'name' => victim_team.name, 'slug' => victim_team.slug, 'url' => victim_team.api_url },
      'organization' => { 'login' => 'evil-org' }, # unrelated org, NOT victim_team.organization
      'member' => { 'login' => victim_user.login },
    )
  end
  assert_includes victim_team.reload.members, victim_user
end
```
Assert: before, `Membership.exists?(team: victim_team, user: victim_user)` is `true` and `victim_team.organization != 'evil-org'`; after calling the handler with `organization.login = 'evil-org'`, the membership must still exist (binding upheld) — the current code fails this because it deletes the membership regardless of `organization` mismatch. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** app/models/shipit/team.rb (L53-58)
```ruby
    def github_team=(github_team)
      self.name = github_team.name
      self.slug = github_team.slug
      self.api_url = github_team.url
      self.github_id = github_team.id
    end
```
