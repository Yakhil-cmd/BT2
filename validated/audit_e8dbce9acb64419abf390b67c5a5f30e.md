### Title
Cross-organization webhook confusion escalates arbitrary GitHub users into `Shipit.github_teams` authorization - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub webhook by picking *which* GitHub App/organization config (and therefore which `webhook_secret`) to validate the HMAC signature against, using a field taken from the untrusted JSON body itself (`repository.owner.login` or `organization.login`). Once that per-organization secret validates, every downstream `Webhooks::Handlers::*` class treats the rest of the same JSON body as fully trusted, including numeric identifiers such as `team.id`, without ever re-checking that those identifiers actually belong to the organization whose secret authenticated the request. `MembershipHandler` uses exactly such an unchecked field (`team.id`) to look up or create the `Shipit::Team` record that backs `Shipit.github_teams` authorization, and then unconditionally adds an attacker-chosen `member.login` to it.

### Finding Description
The webhook signature check resolves the signing organization purely from the payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` selects the `GitHubApp` instance/`webhook_secret` to check `X-Hub-Signature` against based purely on `repository.owner.login` (or `organization.login`), a value taken from the same body being signed: [3](#0-2) 

Multi-organization Shipit deployments configure one `webhook_secret` per organization (`Shipit.github_app_config`), which is only meaningful if events signed with organization A's secret are trusted to only describe organization A's resources: [4](#0-3) 

However, `MembershipHandler` never re-validates that the `team` referenced in the payload belongs to the authenticating organization. It looks up (or creates) a `Team` purely by the attacker-controlled numeric `team.id`, and then unconditionally executes `team.add_member(member)`: [5](#0-4) 

`Shipit::User#authorized?` grants access to the whole application based solely on whether the `User`'s `teams` association intersects `Shipit.github_teams`: [6](#0-5) 

Binding broken (as an equality that no longer holds): *organization that authenticated the webhook* == *organization that owns the `team` acted upon*. The signature check only proves "some request was signed with organization A's secret"; it does not prove "the `team.id`/`member.login` fields inside that request describe organization A's team". Because GitHub team IDs are globally unique numeric identifiers and `Team.find_or_create_by!(github_id: params.team.id)` will happily match an already-synced privileged team record (i.e., one already tracked because it appears in `Shipit.github_teams`) regardless of which organization's secret signed the request, an attacker who controls *any* GitHub organization that is independently onboarded onto the same multi-tenant Shipit instance (and therefore legitimately knows that organization's own `webhook_secret`, set by themselves during onboarding, unrelated to the victim organization) can forge a `membership` event: sign it with their own organization's secret, but set `team.id` to the numeric ID of a privileged team belonging to a completely different, victim organization, and `member.login` to any GitHub login they control.

### Impact Explanation
This directly matches the specified High-severity bullet: "escalation into `Shipit.github_teams` authorization." Adding an attacker-controlled `User` to a `Team` that is one of `Shipit.github_teams` flips `User#authorized?` to `true` for that account, granting it full authenticated access to the Shipit instance — deploy/rollback triggers, stack management, custom tasks with whitelisted env vars, and everything else gated by the `authorized?` check — without the attacker ever being a real member of the victim organization's GitHub team.

### Likelihood Explanation
The exploit only requires the attacker to control one GitHub organization that is independently registered with the same multi-tenant Shipit instance (each organization configures and knows its own `webhook_secret` as part of normal onboarding — this is not a privileged Shipit credential and grants no access to the victim organization by itself). The attacker also needs the numeric GitHub `team.id` of the privileged team, which is discoverable through GitHub's public API (`GET /teams/{team_id}`, or via `GET /orgs/{org}/teams` if the team is not fully private, or by having briefly been a legitimate member and observing `Team#github_id`/`github_team=` assignment). No access to the victim org's repositories, webhook secret, or GitHub App key is required.

### Recommendation
In `MembershipHandler`, verify that `params.organization.login` (the organization the webhook signature was validated against) matches the actual GitHub organization that owns `params.team.id` before creating/reusing the `Team` record, e.g. by re-fetching the team from the GitHub API scoped to that organization, or by storing/checking an `organization` field on `Team` and refusing to add members when it does not match the authenticating organization. More generally, `WebhooksController#verify_signature` should ensure that every organization-scoped identifier used later by a handler (team id, repository full name, etc.) is validated against the same organization that authenticated the request, not trusted independently from the same unauthenticated-until-verified JSON body.

### Proof of Concept
1. Attacker registers/administers GitHub organization `evil-org`, which is (legitimately) tracked by the shared Shipit instance with its own `webhook_secret` in `secrets.github[:evil-org]`.
2. Attacker discovers the numeric GitHub team id `T` of a privileged team belonging to victim organization `good-org`, one of `Shipit.github_teams`.
3. Attacker crafts a `membership` event body:
```json
{
  "action": "added",
  "team": {"id": T, "name": "Privileged Team", "slug": "priv", "url": "https://api.github.com/teams/T"},
  "organization": {"login": "evil-org"},
  "member": {"login": "attacker-controlled-login"}
}
```
4. Attacker computes `X-Hub-Signature` using `evil-org`'s known `webhook_secret` and POSTs it to `/webhooks`.
5. `WebhooksController#verify_signature` resolves `repository_owner` to `"evil-org"` (via `organization.login` fallback since no `repository` key is present), loads `evil-org`'s `GitHubApp`, and the signature validates successfully. [1](#0-0) 
6. `Shipit::Webhooks.for_event('membership')` dispatches to `MembershipHandler`, which looks up `Team.find_or_create_by!(github_id: T)` — matching `good-org`'s already-synced privileged team — creates/fetches `attacker-controlled-login` as a `User`, and calls `team.add_member(member)`. [5](#0-4) 
7. `attacker-controlled-login`'s `Shipit::User#authorized?` now returns `true`, granting full Shipit access despite never having been added to `good-org`'s real GitHub team.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
